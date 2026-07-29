"use strict";

const elements = {
  analysisKicker: document.querySelector("#analysis-kicker"),
  analysisMetrics: document.querySelector("#analysis-metrics"),
  analysisTitle: document.querySelector("#analysis-title"),
  analysisView: document.querySelector("#analysis-view"),
  analyzeButton: document.querySelector("#analyze-button"),
  baselineKicker: document.querySelector("#baseline-kicker"),
  baselineButton: document.querySelector("#baseline-button"),
  baselineMetrics: document.querySelector("#baseline-metrics"),
  baselineView: document.querySelector("#baseline-view"),
  brandContext: document.querySelector("#brand-context"),
  caseList: document.querySelector("#case-list"),
  emptyState: document.querySelector("#empty-state"),
  emptyDescription: document.querySelector("#empty-description"),
  errorBanner: document.querySelector("#error-banner"),
  errorMessage: document.querySelector("#error-message"),
  eventTimeline: document.querySelector("#event-timeline"),
  heroLead: document.querySelector("#hero-lead"),
  incidentPreview: document.querySelector("#incident-preview"),
  incidentSelect: document.querySelector("#incident-select"),
  loadingState: document.querySelector("#loading-state"),
  outputSections: document.querySelector("#output-sections"),
  profileIdentifier: document.querySelector("#profile-identifier"),
  runState: document.querySelector("#run-state"),
  runtimeExternalCalls: document.querySelector("#runtime-external-calls"),
  runtimeLocation: document.querySelector("#runtime-location"),
  runtimeMode: document.querySelector("#runtime-mode"),
  runtimeModel: document.querySelector("#runtime-model"),
  runtimeEffects: document.querySelector("#runtime-effects"),
  runtimeProfile: document.querySelector("#runtime-profile"),
  runtimeSurface: document.querySelector("#runtime-surface"),
  securityDescription: document.querySelector("#security-description"),
  securityIndex: document.querySelector("#security-index"),
  systemStatus: document.querySelector("#system-status"),
  timelineEmpty: document.querySelector("#timeline-empty"),
};

const state = {
  csrfToken: "",
  incidents: [],
  analyzeAvailable: false,
  profile: "loading",
  publicSnapshot: null,
  running: false,
};

const sectionHeadings = new Set([
  "Hechos observados",
  "Fuentes autorizadas",
  "Incertidumbres y datos ausentes",
  "Actuación propuesta",
  "Justificación",
  "Riesgos y límites",
]);

function clearElement(element) {
  element.replaceChildren();
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) {
    element.className = className;
  }
  if (text !== undefined) {
    element.textContent = text;
  }
  return element;
}

function categoryLabel(category) {
  return category.replaceAll("_", " ");
}

function selectedIncident() {
  return state.incidents.find(
    (incident) => incident.id === elements.incidentSelect.value,
  );
}

function updateIncidentPreview() {
  const incident = selectedIncident();
  if (!incident) {
    return;
  }
  clearElement(elements.incidentPreview);
  elements.incidentPreview.append(
    makeElement("span", "category-chip", categoryLabel(incident.category)),
    makeElement("h3", "", incident.title),
    makeElement(
      "p",
      "",
      `${incident.id} · contenido sintético · conocimiento autorizado`,
    ),
  );
}

function setRunState(label, mode = "ready") {
  elements.runState.className = "run-state";
  if (mode === "running") {
    elements.runState.classList.add("is-running");
  }
  if (mode === "complete") {
    elements.runState.classList.add("is-complete");
  }
  clearElement(elements.runState);
  elements.runState.append(makeElement("i"), document.createTextNode(label));
}

function showError(message) {
  elements.errorMessage.textContent = message;
  elements.errorBanner.hidden = false;
  setRunState("Error");
}

function hideError() {
  elements.errorBanner.hidden = true;
  elements.errorMessage.textContent = "";
}

function setBusy(isBusy) {
  state.running = isBusy;
  elements.incidentSelect.disabled = isBusy || state.incidents.length === 0;
  elements.analyzeButton.disabled =
    isBusy || state.incidents.length === 0 || !state.analyzeAvailable;
  elements.baselineButton.disabled = isBusy || state.incidents.length === 0;
  elements.loadingState.hidden = !isBusy;
  if (isBusy) {
    elements.emptyState.hidden = true;
    elements.analysisView.hidden = true;
    elements.baselineView.hidden = true;
    setRunState("Procesando", "running");
  }
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...options,
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("El servicio devolvió una respuesta no válida.");
  }
  if (!response.ok) {
    throw new Error(
      payload?.error?.message || "La operación no está disponible.",
    );
  }
  return payload;
}

function metricCard(label, value) {
  const card = makeElement("div", "metric-card");
  card.append(
    makeElement("span", "", label),
    makeElement("strong", "", String(value)),
  );
  return card;
}

function parseOutput(outputText) {
  const lines = outputText.split("\n");
  const title = lines.shift() || "Resultado";
  const sections = [];
  let current = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    if (sectionHeadings.has(line)) {
      current = { heading: line, lines: [] };
      sections.push(current);
      continue;
    }
    if (current) {
      current.lines.push(line.startsWith("- ") ? line.slice(2) : line);
    }
  }
  return { sections, title };
}

function renderOutputSections(sections) {
  clearElement(elements.outputSections);
  for (const section of sections) {
    const card = makeElement("article", "output-card");
    card.append(makeElement("h4", "", section.heading));
    if (section.lines.length <= 1) {
      card.append(makeElement("p", "", section.lines[0] || "Sin datos."));
    } else {
      const list = makeElement("ul");
      for (const line of section.lines) {
        list.append(makeElement("li", "", line));
      }
      card.append(list);
    }
    elements.outputSections.append(card);
  }
}

function renderTimeline(report) {
  clearElement(elements.eventTimeline);
  const events = report?.events || [];
  for (const event of events) {
    const item = makeElement("li", "event-item");
    item.append(
      makeElement(
        "span",
        "",
        `#${String(event.sequence).padStart(2, "0")} · ${event.outcome}`,
      ),
      makeElement("strong", "", event.kind.replaceAll("_", " ")),
      makeElement("small", "", `${event.source} · ${event.elapsed_ms} ms`),
    );
    elements.eventTimeline.append(item);
  }
  elements.timelineEmpty.hidden = events.length > 0;
  elements.eventTimeline.hidden = events.length === 0;
}

function renderAnalysis(payload) {
  const result = payload.result;
  const parsed = parseOutput(result.output_text);
  const isSnapshot = state.profile === "public_snapshot";
  const isHosted =
    state.profile === "public_llm" || result.external_calls === true;

  elements.analysisKicker.textContent = isSnapshot
    ? "Análisis precomputado"
    : isHosted
      ? "Análisis con LLM"
      : "Análisis completado";
  elements.analysisTitle.textContent = parsed.title;
  clearElement(elements.analysisMetrics);
  elements.analysisMetrics.append(
    metricCard("Categoría", categoryLabel(result.category)),
    metricCard("Invocaciones", result.model_invocations),
    metricCard("Herramientas", result.tool_requests),
    metricCard(
      "Coste",
      result.cost_eur === null ? "Desconocido" : `${result.cost_eur} €`,
    ),
  );
  renderOutputSections(parsed.sections);
  renderTimeline(payload.security_report);
  elements.analysisView.hidden = false;
  elements.baselineView.hidden = true;
  setRunState(
    isSnapshot ? "Snapshot mostrado" : "Completado",
    "complete",
  );
}

function renderBaseline(payload) {
  const result = payload.result;
  elements.baselineKicker.textContent = state.profile.startsWith("public_")
    ? "Baseline precomputada"
    : "Baseline funcional";
  clearElement(elements.baselineMetrics);
  elements.baselineMetrics.append(
    metricCard("Casos", result.summary.cases_total),
    metricCard("Superados", result.summary.cases_passed),
    metricCard("Invocaciones", result.summary.model_invocations),
    metricCard("Llamadas externas", result.summary.external_calls),
  );

  clearElement(elements.caseList);
  for (const item of result.cases) {
    const row = makeElement("article", "case-row");
    row.append(
      makeElement("code", "", item.incident_id),
      makeElement("span", "", categoryLabel(item.category)),
      makeElement("strong", "", item.status.toUpperCase()),
    );
    elements.caseList.append(row);
  }

  renderTimeline(payload.security_report);
  elements.analysisView.hidden = true;
  elements.baselineView.hidden = false;
  setRunState(
    state.profile.startsWith("public_")
      ? "Snapshot mostrado"
      : "Completado",
    "complete",
  );
}

async function runOperation(path, document, renderer) {
  if (state.running) {
    return;
  }
  hideError();
  setBusy(true);
  try {
    const payload = await requestJson(path, {
      body: JSON.stringify(document),
      headers: {
        "Content-Type": "application/json",
        "X-GSL-CSRF": state.csrfToken,
      },
      method: "POST",
    });
    renderer(payload);
  } catch (error) {
    elements.emptyState.hidden = false;
    showError(error instanceof Error ? error.message : "Error inesperado.");
  } finally {
    setBusy(false);
  }
}

function loadIncidentOptions() {
  clearElement(elements.incidentSelect);
  for (const incident of state.incidents) {
    const option = document.createElement("option");
    option.value = incident.id;
    option.textContent = `${incident.id} · ${incident.title}`;
    elements.incidentSelect.append(option);
  }
  updateIncidentPreview();
  setBusy(false);
}

function initializeLocal(payload) {
  state.csrfToken = payload.csrf_token;
  state.incidents = payload.incidents;
  state.analyzeAvailable = payload.capabilities.analyze;
  state.profile = "local";
  state.publicSnapshot = null;

  const hosted = payload.app.provider === "ollama";
  elements.brandContext.textContent = "LAB / LOCAL WORKBENCH";
  elements.heroLead.textContent =
    "Un laboratorio visual para recorrer un análisis defensivo, entender cada control y comprobar los límites explícitos del backend seleccionado.";
  elements.emptyDescription.textContent =
    "Ejecuta un caso para ver el diagnóstico, las métricas y la cadena de decisiones de seguridad.";
  elements.timelineEmpty.textContent =
    "La cronología aparecerá después de ejecutar una operación.";
  elements.profileIdentifier.textContent =
    "GENAI SEGURO LAB · GSL-WEB-001";
  elements.runtimeLocation.textContent = "Loopback";
  elements.runtimeMode.textContent = hosted
    ? "LLM alojado · experimental"
    : "Determinista";
  elements.runtimeModel.textContent = hosted
    ? "LLM alojado"
    : payload.app.model;
  elements.runtimeExternalCalls.textContent = hosted
    ? "2 por análisis"
    : "0";
  elements.runtimeSurface.textContent = "Loopback";
  elements.runtimeProfile.textContent = "Local · educativo · no productivo";
  elements.securityIndex.textContent = "03 / TELEMETRÍA EFÍMERA";
  elements.securityDescription.textContent =
    "Eventos saneados, encadenados y mantenidos únicamente durante esta operación.";
  elements.runtimeEffects.textContent = hosted
    ? "Analyze realiza dos llamadas al LLM alojado; baseline permanece local y determinista. No se escriben ni persisten resultados."
    : "Analyze y baseline son locales y deterministas. No se escriben archivos ni persisten resultados.";
  elements.analyzeButton.querySelector("span").textContent = hosted
    ? "Análisis con LLM"
    : "Analizar incidente";
  elements.baselineButton.textContent =
    "Ejecutar baseline determinista de 12 casos";
  elements.systemStatus.textContent = state.analyzeAvailable
    ? "Operativo"
    : "Solo baseline";
  loadIncidentOptions();
}

function validatePublicSnapshot(snapshot) {
  if (
    snapshot?.profile !== "public_static_snapshot"
    || !Array.isArray(snapshot.incidents)
    || snapshot.incidents.length !== 12
    || typeof snapshot.analyses !== "object"
    || snapshot.analyses === null
    || typeof snapshot.baseline !== "object"
    || snapshot.baseline === null
    || snapshot.runtime?.external_calls !== false
    || snapshot.runtime?.cost_eur !== 0
  ) {
    throw new Error("El snapshot público no cumple su contrato.");
  }
}

function initializePublicSnapshot(snapshot) {
  validatePublicSnapshot(snapshot);
  state.csrfToken = "";
  state.incidents = snapshot.incidents;
  state.analyzeAvailable = true;
  state.profile = "public_snapshot";
  state.publicSnapshot = snapshot;

  elements.brandContext.textContent = "LAB / PUBLIC SNAPSHOT";
  elements.heroLead.textContent =
    "Una demostración de solo lectura para explorar análisis defensivos, métricas y controles ya materializados en evidencia precomputada.";
  elements.emptyDescription.textContent =
    "Selecciona un caso para mostrar el diagnóstico, las métricas y la cadena de seguridad precomputados.";
  elements.timelineEmpty.textContent =
    "La cronología precomputada aparecerá al mostrar un análisis o la baseline.";
  elements.profileIdentifier.textContent =
    "GENAI SEGURO LAB · GSL-PUBLIC-STATIC-001";
  elements.runtimeLocation.textContent = "Vercel · estático";
  elements.runtimeMode.textContent = "Demo pública · snapshot determinista";
  elements.runtimeModel.textContent = snapshot.runtime.model;
  elements.runtimeExternalCalls.textContent = "0";
  elements.runtimeSurface.textContent = "CDN estático";
  elements.runtimeProfile.textContent =
    "Demo pública · snapshot determinista";
  elements.securityIndex.textContent = "03 / EVIDENCIA PRECOMPUTADA";
  elements.securityDescription.textContent =
    "Eventos saneados y encadenados materializados previamente por el generador determinista.";
  elements.runtimeEffects.textContent =
    "Esta página solo lee archivos estáticos precomputados. No ejecuta modelos, herramientas, POST ni llamadas externas.";
  elements.analyzeButton.querySelector("span").textContent =
    "Mostrar análisis precomputado";
  elements.baselineButton.textContent = "Mostrar baseline precomputada";
  elements.systemStatus.textContent = "Snapshot disponible";
  loadIncidentOptions();
}

function initializePublicLLM(payload, snapshot) {
  validatePublicSnapshot(snapshot);
  if (
    payload?.app?.mode !== "public_llm"
    || !Array.isArray(payload.incidents)
    || payload.incidents.length !== 12
    || typeof payload.csrf_token !== "string"
    || typeof payload.capabilities?.analyze !== "boolean"
    || payload.capabilities?.baseline !== true
  ) {
    throw new Error("El perfil público alojado no cumple su contrato.");
  }

  state.csrfToken = payload.csrf_token;
  state.incidents = payload.incidents;
  state.analyzeAvailable = payload.capabilities.analyze;
  state.profile = "public_llm";
  state.publicSnapshot = snapshot;

  elements.brandContext.textContent = "LAB / PUBLIC LLM";
  elements.heroLead.textContent =
    "Una demostración pública para analizar un incidente sintético con un LLM alojado y contrastarlo con la baseline precomputada.";
  elements.emptyDescription.textContent = state.analyzeAvailable
    ? "Selecciona un caso para ejecutar Análisis con LLM o consultar la baseline precomputada."
    : "El análisis alojado está deshabilitado; la baseline precomputada continúa disponible.";
  elements.timelineEmpty.textContent =
    "La cronología saneada aparecerá después de un análisis o al mostrar la baseline.";
  elements.profileIdentifier.textContent =
    "GENAI SEGURO LAB · GSL-PUBLIC-LLM-001";
  elements.runtimeLocation.textContent = "Vercel Functions";
  elements.runtimeMode.textContent = state.analyzeAvailable
    ? "Análisis con LLM"
    : "LLM deshabilitado";
  elements.runtimeModel.textContent = "LLM alojado";
  elements.runtimeExternalCalls.textContent = state.analyzeAvailable
    ? "2 por análisis"
    : "0 · kill switch";
  elements.runtimeSurface.textContent = "Mismo origen · API cerrada";
  elements.runtimeProfile.textContent =
    "Público · sintético · sin persistencia";
  elements.securityIndex.textContent = "03 / TELEMETRÍA EFÍMERA";
  elements.securityDescription.textContent =
    "Eventos saneados de la operación actual; no se muestran prompts, respuestas remotas ni huellas internas.";
  elements.runtimeEffects.textContent = state.analyzeAvailable
    ? "Análisis con LLM realiza dos llamadas alojadas; catálogo y baseline proceden del snapshot. No se persisten resultados."
    : "El kill switch impide el análisis alojado. Catálogo y baseline precomputada permanecen disponibles.";
  elements.analyzeButton.querySelector("span").textContent =
    "Análisis con LLM";
  elements.baselineButton.textContent = "Mostrar baseline precomputada";
  elements.systemStatus.textContent = state.analyzeAvailable
    ? "LLM habilitado"
    : "Solo baseline";
  loadIncidentOptions();
}

async function initialize() {
  try {
    const status = await requestJson("/api/status");
    if (status?.app?.mode === "public_llm") {
      initializePublicLLM(
        status,
        await requestJson("/snapshots/public-profile-v1.json"),
      );
    } else {
      initializeLocal(status);
    }
    return;
  } catch {
    try {
      initializePublicSnapshot(
        await requestJson("/snapshots/public-profile-v1.json"),
      );
      return;
    } catch (error) {
      elements.systemStatus.textContent = "No disponible";
      showError(
        error instanceof Error
          ? error.message
          : "No se pudo cargar el perfil del laboratorio.",
      );
    }
  }
}

function showSelectedAnalysis() {
  const incident = selectedIncident();
  if (!incident) {
    return;
  }
  if (state.profile === "public_snapshot") {
    const payload = state.publicSnapshot.analyses[incident.id];
    if (!payload) {
      showError("El análisis precomputado no está disponible.");
      return;
    }
    hideError();
    elements.emptyState.hidden = true;
    renderAnalysis(payload);
    return;
  }
  runOperation(
    "/api/analyze",
    { incident_id: incident.id },
    renderAnalysis,
  );
}

function showBaseline() {
  if (state.profile.startsWith("public_")) {
    hideError();
    elements.emptyState.hidden = true;
    renderBaseline(state.publicSnapshot.baseline);
    return;
  }
  runOperation("/api/baseline", {}, renderBaseline);
}

elements.incidentSelect.addEventListener("change", updateIncidentPreview);
elements.analyzeButton.addEventListener("click", showSelectedAnalysis);
elements.baselineButton.addEventListener("click", showBaseline);

initialize();
