/* Guardian Figma collector contract v1. Read-only by construction. */
(function guardianFigmaCollectorModule(globalObject) {
  "use strict";

  const CONTRACT = Object.freeze({
    adapter: "figma",
    adapterVersion: "0.1.0",
    contract: "guardian-figma-plugin-api-readback",
    contractVersion: 1,
    evidenceSchema: "figma-observation-v1",
    proofMethod: "figma_plugin_api_readback",
    readOnly: true,
    bindingFields: [
      "collectorDigest",
      "configDigest",
      "policyDigest",
      "profileId",
      "projectBindingDigest",
      "runId",
      "snapshotId",
      "sourceCutDigest",
    ],
    collectorAuthority: "unprotected_caller_carried",
    productCopyCollected: false,
  });

  const FIELD_CATEGORIES = Object.freeze({
    fills: "colors",
    strokes: "colors",
    opacity: "effects",
    effects: "effects",
    layoutGrids: "spacing",
    width: "spacing",
    height: "spacing",
    minWidth: "spacing",
    maxWidth: "spacing",
    minHeight: "spacing",
    maxHeight: "spacing",
    itemSpacing: "spacing",
    counterAxisSpacing: "spacing",
    paddingLeft: "spacing",
    paddingRight: "spacing",
    paddingTop: "spacing",
    paddingBottom: "spacing",
    strokeWeight: "spacing",
    strokeTopWeight: "spacing",
    strokeRightWeight: "spacing",
    strokeBottomWeight: "spacing",
    strokeLeftWeight: "spacing",
    cornerRadius: "radii",
    topLeftRadius: "radii",
    topRightRadius: "radii",
    bottomLeftRadius: "radii",
    bottomRightRadius: "radii",
    fontName: "typography",
    fontSize: "typography",
    fontWeight: "typography",
    lineHeight: "typography",
    letterSpacing: "typography",
    paragraphSpacing: "typography",
    paragraphIndent: "typography",
    reactions: "motion",
  });

  const STYLE_FIELDS = Object.freeze([
    ["fillStyleId", "paint", "colors", ["fills"]],
    ["strokeStyleId", "paint", "colors", ["strokes"]],
    ["effectStyleId", "effect", "effects", ["effects"]],
    ["gridStyleId", "grid", "spacing", ["layoutGrids"]],
    [
      "textStyleId",
      "text",
      "typography",
      [
        "fontName",
        "fontSize",
        "fontWeight",
        "lineHeight",
        "letterSpacing",
        "paragraphSpacing",
        "paragraphIndent",
      ],
    ],
  ]);

  class CollectorContractError extends Error {}

  function requireString(value, field) {
    if (typeof value !== "string" || value.length === 0) {
      throw new CollectorContractError(field + " must be a non-empty string");
    }
    return value;
  }

  function canonicalValue(value) {
    if (value === null || typeof value === "string" || typeof value === "boolean") {
      return value;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new CollectorContractError("Non-finite Figma value");
      return value;
    }
    if (typeof value === "symbol") return "__figma_mixed__";
    if (typeof value === "undefined") return "__undefined__";
    if (Array.isArray(value)) return value.map(canonicalValue);
    if (typeof value === "object") {
      const output = {};
      for (const key of Object.keys(value).sort()) {
        if (typeof value[key] !== "function") output[key] = canonicalValue(value[key]);
      }
      return output;
    }
    return String(value);
  }

  function canonicalJson(value) {
    return JSON.stringify(canonicalValue(value));
  }

  async function sha256(value) {
    if (
      typeof globalObject.TextEncoder !== "function" ||
      !globalObject.crypto ||
      !globalObject.crypto.subtle
    ) {
      throw new CollectorContractError("SHA-256 runtime is unavailable");
    }
    const bytes = new globalObject.TextEncoder().encode(canonicalJson(value));
    const digest = await globalObject.crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (item) => item.toString(16).padStart(2, "0")).join("");
  }

  function reverseBindings(config, bindingType) {
    const output = new Map();
    for (const identity of Object.keys(config.tokenBindings || {}).sort()) {
      const binding = config.tokenBindings[identity];
      if (binding && binding.bindingType === bindingType) output.set(binding.key, identity);
    }
    return output;
  }

  function assetIndexes(config) {
    const byKey = new Map();
    const byWorkingNode = new Map();
    for (const identity of Object.keys(config.assets || {}).sort()) {
      const item = config.assets[identity];
      if (item && item.assetKey) byKey.set(item.assetKey, identity);
      for (const signed of (item && item.workingFileInstances) || []) {
        const locator = signed.fileKey + "\u0000" + signed.nodeId;
        if (byWorkingNode.has(locator)) {
          throw new CollectorContractError("Working instance locator is ambiguous");
        }
        byWorkingNode.set(locator, identity);
      }
    }
    return { byKey, byWorkingNode };
  }

  function validateInputs(config, context, api) {
    if (!config || config.adapter !== "figma" || config.adapterVersion !== "0.1.0") {
      throw new CollectorContractError("Unsupported Guardian Figma config");
    }
    for (const field of [
      "runId",
      "profileId",
      "policyDigest",
      "snapshotId",
      "sourceCutDigest",
      "projectBindingDigest",
      "configDigest",
      "collectorDigest",
    ]) requireString(config[field], "config." + field);
    if (!context || !context.document || !context.source) {
      throw new CollectorContractError("Pinned document and source context are required");
    }
    requireString(context.document.fileKey, "document.fileKey");
    requireString(context.document.sourceVersion, "document.sourceVersion");
    if (!Array.isArray(context.document.rootNodeIds) || context.document.rootNodeIds.length === 0) {
      throw new CollectorContractError("At least one root node is required");
    }
    const roots = [...new Set(context.document.rootNodeIds)].sort();
    if (canonicalJson(roots) !== canonicalJson(context.document.rootNodeIds)) {
      throw new CollectorContractError("Root node IDs must be sorted and unique");
    }
    const pinnedVersion = config.documents && config.documents[context.document.fileKey];
    if (!pinnedVersion) throw new CollectorContractError("Document is outside the pinned source cut");
    if (!api || typeof api.getNodeByIdAsync !== "function") return "unsupported";
    return "ready";
  }

  function bindingEnvelope(config) {
    return {
      runId: config.runId,
      profileId: config.profileId,
      policyDigest: config.policyDigest,
      snapshotId: config.snapshotId,
      sourceCutDigest: config.sourceCutDigest,
      projectBindingDigest: config.projectBindingDigest,
      configDigest: config.configDigest,
      collectorDigest: config.collectorDigest,
    };
  }

  function sourceEnvelope(context, complete, available) {
    return {
      state: requireString(context.source.state, "source.state"),
      available,
      complete,
    };
  }

  function emptyResult(config, context, status, available, complete) {
    return {
      schemaVersion: 1,
      adapter: "figma",
      adapterVersion: "0.1.0",
      status,
      binding: bindingEnvelope(config),
      source: sourceEnvelope(context, complete, available),
      document: {
        fileKey: context.document.fileKey,
        sourceVersion: context.document.sourceVersion,
        rootNodeIds: [...context.document.rootNodeIds],
      },
      analysis: {
        method: "figma_plugin_api_readback",
        complete: false,
        assessedNodes: 0,
        totalNodes: 0,
        assessedFields: 0,
        totalFields: 0,
      },
      observations: [],
    };
  }

  function aliases(value) {
    if (Array.isArray(value)) return value;
    return value ? [value] : [];
  }

  async function resolveVariableAlias(alias, api) {
    if (!alias || alias.type !== "VARIABLE_ALIAS" || !alias.id) {
      throw new CollectorContractError("Bound variable alias is malformed");
    }
    const variable = await api.variables.getVariableByIdAsync(alias.id);
    if (!variable) throw new CollectorContractError("Bound variable cannot be resolved");
    const collection = await api.variables.getVariableCollectionByIdAsync(
      variable.variableCollectionId,
    );
    if (!collection) throw new CollectorContractError("Variable collection cannot be resolved");
    return { variable, collection };
  }

  async function inferredKeys(node, field, api) {
    const inferred = node.inferredVariables && node.inferredVariables[field];
    const keys = [];
    for (const alias of aliases(inferred)) {
      try {
        const resolved = await resolveVariableAlias(alias, api);
        keys.push(resolved.variable.key);
      } catch (_) {
        keys.push("unresolved:" + String(alias && alias.id ? alias.id : "unknown"));
      }
    }
    return [...new Set(keys)].sort();
  }

  function fieldCategory(field) {
    return FIELD_CATEGORIES[field] || null;
  }

  async function collectBoundVariables(node, config, api, output, covered) {
    const boundVariables = node.boundVariables;
    if (!boundVariables || typeof boundVariables !== "object") return;
    const variableIdentities = reverseBindings(config, "variable");
    for (const field of Object.keys(boundVariables).sort()) {
      if (field === "characters") continue;
      const category = fieldCategory(field);
      if (!category) {
        throw new CollectorContractError("Unsupported bound variable field: " + field);
      }
      const values = aliases(boundVariables[field]);
      for (let index = 0; index < values.length; index += 1) {
        const alias = values[index];
        if (!alias) continue;
        const resolved = await resolveVariableAlias(alias, api);
        const path = values.length > 1 ? field + "." + index : field;
        covered.add(path);
        const identity =
          variableIdentities.get(resolved.variable.key) ||
          "unapproved-variable:" + resolved.variable.key;
        output.push({
          kind: "variable",
          category,
          nodeId: node.id,
          field: path,
          identity,
          variableKey: resolved.variable.key,
          collectionKey: resolved.collection.key,
          resolvedType: resolved.variable.resolvedType,
        });
      }
    }
  }

  async function styleObservation(node, field, expectedType, category, range, styleId, api, identities) {
    const style = await api.getStyleByIdAsync(styleId);
    if (!style || String(style.type || "").toLowerCase() !== expectedType) {
      throw new CollectorContractError("Applied Figma style cannot be resolved exactly");
    }
    return {
      kind: "style",
      category,
      nodeId: node.id,
      field,
      identity: identities.get(style.key) || "unapproved-style:" + style.key,
      styleKey: style.key,
      styleType: expectedType,
      range,
    };
  }

  async function collectStyles(node, config, api, output, styleCovered) {
    const identities = reverseBindings(config, "style");
    for (const [field, expectedType, category, properties] of STYLE_FIELDS) {
      if (!(field in node)) continue;
      const styleId = node[field];
      if (typeof styleId === "string" && styleId.length > 0) {
        output.push(
          await styleObservation(node, field, expectedType, category, null, styleId, api, identities),
        );
        for (const property of properties) styleCovered.add(property);
      } else if (
        expectedType === "text" &&
        styleId === api.mixed &&
        typeof node.getStyledTextSegments === "function"
      ) {
        const segments = node.getStyledTextSegments(["textStyleId"]);
        for (const segment of segments) {
          if (typeof segment.textStyleId !== "string" || !segment.textStyleId) {
            output.push({
              kind: "unassessed",
              category,
              nodeId: node.id,
              field,
              reason: "mixed_text_range_has_no_style",
            });
            continue;
          }
          output.push(
            await styleObservation(
              node,
              field,
              expectedType,
              category,
              { start: segment.start, end: segment.end },
              segment.textStyleId,
              api,
              identities,
            ),
          );
        }
        for (const property of properties) styleCovered.add(property);
      }
    }
  }

  function hasValue(value, mixed) {
    if (value === null || typeof value === "undefined") return false;
    if (value === mixed) return true;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === "string") return value.length > 0;
    return true;
  }

  async function collectRawValues(node, api, output, covered, styleCovered) {
    for (const field of Object.keys(FIELD_CATEGORIES).sort()) {
      if (!(field in node) || styleCovered.has(field)) continue;
      const value = node[field];
      if (!hasValue(value, api.mixed)) continue;
      const values = Array.isArray(value) ? value : [value];
      for (let index = 0; index < values.length; index += 1) {
        const path = values.length > 1 ? field + "." + index : field;
        if (covered.has(path) || covered.has(field)) continue;
        if (values[index] === api.mixed) {
          output.push({
            kind: "unassessed",
            category: FIELD_CATEGORIES[field],
            nodeId: node.id,
            field: path,
            reason: "mixed_value_requires_range_readback",
          });
          continue;
        }
        output.push({
          kind: "raw",
          category: FIELD_CATEGORIES[field],
          nodeId: node.id,
          field: path,
          valueDigest: await sha256(values[index]),
          inferredVariableKeys: await inferredKeys(node, field, api),
        });
      }
    }
  }

  function componentProperties(node, expected) {
    const output = {};
    const unapprovedFields = [];
    const source = node.componentProperties || {};
    const approved = expected && expected.properties ? expected.properties : {};
    for (const key of Object.keys(source).sort()) {
      const property = source[key] || {};
      // Ordinary product copy is outside design-token governance. Never place
      // its value, raw or hashed, in collector evidence.
      if (property.type === "TEXT") continue;
      const value = property.value;
      if (Object.prototype.hasOwnProperty.call(approved, key)) {
        if (value !== null && typeof value !== "undefined") output[key] = String(value);
      } else {
        unapprovedFields.push("componentProperties." + key);
      }
    }
    return { properties: output, unapprovedFields };
  }

  function overrideFields(node) {
    const fields = [];
    for (const item of node.overrides || []) {
      for (const field of item.overriddenFields || []) fields.push(String(field));
    }
    return [...new Set(fields)].sort();
  }

  function selectedVariant(expected, properties, mainComponent) {
    const allowed = Array.isArray(expected && expected.variants) ? expected.variants : [];
    if (allowed.length === 0) return null;
    const candidates = Object.values(properties).filter((value) => allowed.includes(value));
    if (candidates.length === 1) return candidates[0];
    if (mainComponent && allowed.includes(mainComponent.name)) return mainComponent.name;
    return null;
  }

  async function collectAsset(node, config, context, api, output, indexes) {
    const workingIdentity = indexes.byWorkingNode.get(
      context.document.fileKey + "\u0000" + node.id,
    );
    if (node.type !== "INSTANCE" && !workingIdentity) return;
    const mainComponent =
      node.type === "INSTANCE" ? await node.getMainComponentAsync() : null;
    const key = mainComponent && mainComponent.key ? mainComponent.key : "unresolved-detached";
    const identity = workingIdentity || indexes.byKey.get(key) || "unapproved-asset:" + key;
    const expected = config.assets[identity] || null;
    const collectedProperties =
      node.type === "INSTANCE"
        ? componentProperties(node, expected)
        : { properties: {}, unapprovedFields: [] };
    const properties = collectedProperties.properties;
    const unapprovedOverrideFields =
      node.type === "INSTANCE"
        ? [
            ...new Set([
              ...overrideFields(node),
              ...collectedProperties.unapprovedFields,
            ]),
          ].sort()
        : [];
    const category = expected && expected.category === "icons" ? "icons" : "components";
    output.push({
      kind: "asset",
      category,
      nodeId: node.id,
      field: "instance",
      identity,
      figmaInstance: {
        fileKey: context.document.fileKey,
        nodeId: node.id,
        sourceVersion: context.document.sourceVersion,
        nodeType: node.type,
        canonicalAssetKey: key,
        remote: Boolean(mainComponent && mainComponent.remote),
        variant: selectedVariant(expected, properties, mainComponent),
        properties,
        unapprovedOverrideFields,
      },
    });
  }

  function childNodes(node) {
    return node && Array.isArray(node.children) ? node.children : [];
  }

  async function collectGuardianFigmaObservation(config, context, api) {
    api = api || globalObject.figma;
    const readiness = validateInputs(config, context, api);
    if (readiness === "unsupported") {
      return emptyResult(config, context, "unsupported", true, true);
    }
    if (context.source.available !== true) {
      return emptyResult(config, context, "source_unavailable", false, false);
    }
    if (context.source.complete !== true) {
      return emptyResult(config, context, "source_incomplete", true, false);
    }
    if (!api.variables || typeof api.variables.getVariableByIdAsync !== "function") {
      return emptyResult(config, context, "unsupported", true, true);
    }
    if (api.fileKey && api.fileKey !== context.document.fileKey) {
      return emptyResult(config, context, "source_incomplete", true, false);
    }

    const observations = [];
    const indexes = assetIndexes(config);
    try {
      const queue = [];
      for (const rootId of context.document.rootNodeIds) {
        const root = await api.getNodeByIdAsync(rootId);
        if (!root) throw new CollectorContractError("Pinned Figma root cannot be read");
        queue.push(root);
      }
      const seen = new Set();
      while (queue.length > 0) {
        const node = queue.shift();
        if (!node || seen.has(node.id)) continue;
        seen.add(node.id);
        for (const child of childNodes(node)) queue.push(child);
        if (typeof node.id !== "string" || !("type" in node)) continue;
        const covered = new Set();
        const styleCovered = new Set();
        await collectBoundVariables(node, config, api, observations, covered);
        await collectStyles(node, config, api, observations, styleCovered);
        await collectRawValues(node, api, observations, covered, styleCovered);
        await collectAsset(node, config, context, api, observations, indexes);
      }
    } catch (error) {
      if (error instanceof CollectorContractError) {
        return emptyResult(config, context, "source_incomplete", true, false);
      }
      throw error;
    }

    observations.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
    const assessedNodes = new Set(observations.map((item) => item.nodeId)).size;
    return {
      schemaVersion: 1,
      adapter: "figma",
      adapterVersion: "0.1.0",
      status: "allowed",
      binding: bindingEnvelope(config),
      source: sourceEnvelope(context, true, true),
      document: {
        fileKey: context.document.fileKey,
        sourceVersion: context.document.sourceVersion,
        rootNodeIds: [...context.document.rootNodeIds],
      },
      analysis: {
        method: "figma_plugin_api_readback",
        complete: true,
        assessedNodes,
        totalNodes: assessedNodes,
        assessedFields: observations.length,
        totalFields: observations.length,
      },
      observations,
    };
  }

  const exported = Object.freeze({
    CONTRACT,
    CollectorContractError,
    collectGuardianFigmaObservation,
  });
  if (typeof module !== "undefined" && module.exports) module.exports = exported;
  globalObject.GuardianFigmaCollector = exported;
})(typeof globalThis === "undefined" ? this : globalThis);
