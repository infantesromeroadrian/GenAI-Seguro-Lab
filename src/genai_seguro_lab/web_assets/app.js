"use strict";

const elements = {
  analysisMetrics: document.querySelector("#analysis-metrics"),
  analysisTitle: document.querySelector("#analysis-title"),
  analysisView: document.querySelector("#analysis-view"),
  analyzeButton: document.querySelector("#analyze-button"),
  baselineButton: document.querySelector("#baseline-button"),
  baselineMetrics: document.querySelector("#baseline-metrics"),
  baselineView: document.querySelector("#baseline-view"),
  caseList: document.querySelector("#case-list"),
  emptyState: document.querySelector("#empty-state"),
  errorBanner: document.querySelector("#error-banner"),
  errorMessage: document.querySelector("#error-message"),
  eventTimeline: document.querySelector("#event-timeline"),
  incidentPreview: document.querySelector("#incident-preview"),
  incidentSelect: document.querySelector("#incident-select"),
  loadingState: document.querySelector("#loading-state"),
  outputSections: document.querySelector("#output-sections"),
  runState: document.querySelector("#run-state"),
  systemStatus: document.querySelector("#system-status"),
  timelineEmpty: document.querySelector("#timeline-empty"),
};

const state = {
  csrfToken: "",
  incidents: [],
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
  elements.analyzeButton.disabled = isBusy || state.incidents.length === 0;
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

  elements.analysisTitle.textContent = parsed.title;
  clearElement(elements.analysisMetrics);
  elements.analysisMetrics.append(
    metricCard("Categoría", categoryLabel(result.category)),
    metricCard("Invocaciones", result.model_invocations),
    metricCard("Herramientas", result.tool_requests),
    metricCard("Coste", `${result.cost_eur} €`),
  );
  renderOutputSections(parsed.sections);
  renderTimeline(payload.security_report);
  elements.analysisView.hidden = false;
  elements.baselineView.hidden = true;
  setRunState("Completado", "complete");
}

function renderBaseline(payload) {
  const result = payload.result;
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
  setRunState("Completado", "complete");
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

async function initialize() {
  try {
    const payload = await requestJson("/api/status");
    state.csrfToken = payload.csrf_token;
    state.incidents = payload.incidents;

    clearElement(elements.incidentSelect);
    for (const incident of state.incidents) {
      const option = document.createElement("option");
      option.value = incident.id;
      option.textContent = `${incident.id} · ${incident.title}`;
      elements.incidentSelect.append(option);
    }

    elements.systemStatus.textContent = "Operativo";
    updateIncidentPreview();
    setBusy(false);
  } catch (error) {
    elements.systemStatus.textContent = "No disponible";
    showError(
      error instanceof Error
        ? error.message
        : "No se pudo conectar con el laboratorio.",
    );
  }
}

elements.incidentSelect.addEventListener("change", updateIncidentPreview);
elements.analyzeButton.addEventListener("click", () => {
  const incident = selectedIncident();
  if (incident) {
    runOperation(
      "/api/analyze",
      { incident_id: incident.id },
      renderAnalysis,
    );
  }
});
elements.baselineButton.addEventListener("click", () => {
  runOperation("/api/baseline", {}, renderBaseline);
});

initialize();
