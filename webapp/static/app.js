const form = document.getElementById('search-form');
const qInput = document.getElementById('q');
const onlyLeaksInput = document.getElementById('only-leaks');
const resultsBody = document.getElementById('results-body');
const resultsTitle = document.getElementById('results-title');
const scanLine = document.getElementById('scan-line');
const pagination = document.getElementById('pagination');
const prevPageBtn = document.getElementById('prev-page');
const nextPageBtn = document.getElementById('next-page');
const pageIndicator = document.getElementById('page-indicator');

const detailOverlay = document.getElementById('detail-overlay');
const detailClose = document.getElementById('detail-close');
const detailBack = document.getElementById('detail-back');

const tabDashboard = document.getElementById('tab-dashboard');
const tabSearch = document.getElementById('tab-search');
const viewDashboard = document.getElementById('view-dashboard');
const viewSearch = document.getElementById('view-search');
const statStrip = document.getElementById('stat-strip');

const relationTabsEl = document.getElementById('relation-tabs');
const relationActiveLabel = document.getElementById('relation-active-label');
const relationExpandBtn = document.getElementById('relation-expand-btn');
const relationModalOverlay = document.getElementById('relation-modal-overlay');
const relationModalClose = document.getElementById('relation-modal-close');
const relationModalAddress = document.getElementById('relation-modal-address');
const relationModalTabsEl = document.getElementById('relation-modal-tabs');
const relationModalActiveLabel = document.getElementById('relation-modal-active-label');
const relationModalCanvas = document.getElementById('relation-modal-canvas');
const relationModalCanvas3dWrap = document.getElementById('relation-modal-canvas-3d-wrap');
const relationModalCanvas3d = document.getElementById('relation-modal-canvas-3d');
const relationModalHintEl = document.getElementById('relation-modal-hint');
const relationViewModeToggle = document.getElementById('relation-view-mode-toggle');
const relation3dResetBtn = document.getElementById('relation-3d-reset-btn');
const relationFullscreenBtn = document.getElementById('relation-fullscreen-btn');
const relationNeo4jQuery = document.getElementById('relation-neo4j-query');
const relationNeo4jCopy = document.getElementById('relation-neo4j-copy');
const relation3dNodePanel = document.getElementById('relation-3d-node-panel');
const relation3dNodePanelAddress = document.getElementById('relation-3d-node-panel-address');
const relation3dNodePanelBody = document.getElementById('relation-3d-node-panel-body');
const relation3dNodePanelClose = document.getElementById('relation-3d-node-panel-close');
const relation3dNodePanelFullBtn = document.getElementById('relation-3d-node-panel-full-btn');

let relationState = { address: null, grouped: {}, doc: null, activeType: 'all', modalActiveType: 'all', viewMode: '2d' };

let detailHistory = [];

const PAGE_SIZE = 50;
let currentPage = 1;
let currentTotal = 0;
let mode = 'list'; // 'list' | 'search'
let activeFilter = 'all'; // 'all' | 'alive' | 'leaks'
let docsByAddress = {};

const statButtons = {
  all: document.getElementById('stat-btn-total'),
  alive: document.getElementById('stat-btn-alive'),
  leaks: document.getElementById('stat-btn-leaks'),
  relations: document.getElementById('stat-btn-relations'),
};

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function formatDate(iso) {
  if (!iso) return 'Sin fecha';
  try {
    return new Date(iso).toLocaleString('es-ES');
  } catch {
    return iso;
  }
}

async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    document.getElementById('stat-total').textContent = data.total ?? '0';
    document.getElementById('stat-alive').textContent = data.by_status?.alive ?? 0;
    document.getElementById('stat-leaks').textContent = data.with_leaks ?? '0';
    document.getElementById('stat-relations').textContent = data.with_relations ?? '0';
  } catch {
    document.getElementById('stat-total').textContent = 'N/D';
    document.getElementById('stat-alive').textContent = 'N/D';
    document.getElementById('stat-leaks').textContent = 'N/D';
    document.getElementById('stat-relations').textContent = 'N/D';
  }
}

function rememberDocs(results) {
  docsByAddress = {};
  results.forEach((r) => { docsByAddress[r.address] = r; });
}

function renderResults(results) {
  rememberDocs(results);

  if (!results.length) {
    resultsBody.innerHTML = '<p class="empty-state">Sin resultados. Prueba con otra palabra clave.</p>';
    return;
  }

  resultsBody.innerHTML = results.map((r) => {
    const title = r.http_title
      ? `<p class="result-title">${escapeHtml(r.http_title)}</p>`
      : `<p class="result-title is-empty">Sin titulo HTTP disponible</p>`;

    const badges = [];
    (r.technologies || []).forEach((t) => badges.push(`<span class="badge badge--tech">${escapeHtml(t)}</span>`));
    (r.open_ports || []).forEach((p) => badges.push(`<span class="badge badge--port">${escapeHtml(p)}</span>`));
    if (r.has_tls_cert) badges.push('<span class="badge badge--leak">TLS</span>');
    if (r.has_jarm) badges.push('<span class="badge badge--leak">JARM</span>');
    if (r.has_ssh_key) badges.push('<span class="badge badge--leak">SSH</span>');
    if (r.has_pgp_key) badges.push('<span class="badge badge--leak">PGP</span>');
    if (r.has_crypto_address) badges.push('<span class="badge badge--leak">CRIPTO</span>');
    if (r.has_javascript) badges.push('<span class="badge badge--leak">JS</span>');
    if (r.has_css) badges.push('<span class="badge badge--leak">CSS</span>');
    if (r.has_favicon) badges.push('<span class="badge badge--leak">FAVICON</span>');
    if (r.has_document) badges.push('<span class="badge badge--leak">DOC</span>');
    if (r.has_relations) badges.push('<span class="badge badge--port">RELACIONADO</span>');

    return `
      <article class="result-row" tabindex="0" role="button" data-address="${escapeHtml(r.address)}">
        <span class="result-address">${escapeHtml(r.address)}</span>
        <span class="badge ${r.status === 'alive' ? 'badge--alive' : ''}">${escapeHtml(r.status || 'desconocido')}</span>
        ${title}
        <div class="result-badges">${badges.join('')}</div>
      </article>
    `;
  }).join('');

  resultsBody.querySelectorAll('.result-row').forEach((row) => {
    row.addEventListener('click', () => openDetailByAddress(row.dataset.address));
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDetailByAddress(row.dataset.address); }
    });
  });
}

function updatePaginationUI() {
  const totalPages = Math.max(Math.ceil(currentTotal / PAGE_SIZE), 1);
  pagination.hidden = mode !== 'list' || currentTotal <= PAGE_SIZE;
  prevPageBtn.disabled = currentPage <= 1;
  nextPageBtn.disabled = currentPage >= totalPages;
  pageIndicator.textContent = `Pagina ${currentPage} de ${totalPages}`;
}

function updateActiveStatButton() {
  Object.entries(statButtons).forEach(([key, btn]) => {
    btn.classList.toggle('is-active', mode === 'list' && activeFilter === key);
  });
}

function filterLabel(filter) {
  if (filter === 'alive') return 'Dominios activos';
  if (filter === 'leaks') return 'Dominios con fugas';
  if (filter === 'relations') return 'Dominios con relaciones de infraestructura';
  return 'Listado';
}

async function loadList(page = 1, filter = activeFilter) {
  mode = 'list';
  currentPage = page;
  activeFilter = filter;
  updateActiveStatButton();
  scanLine.hidden = false;
  try {
    const params = new URLSearchParams({ page, size: PAGE_SIZE });
    if (filter === 'alive') params.set('status', 'alive');
    if (filter === 'leaks') params.set('only_leaks', 'true');
    if (filter === 'relations') params.set('only_relations', 'true');

    const res = await fetch(`/api/list?${params.toString()}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    currentTotal = data.total;
    resultsTitle.textContent = `${filterLabel(filter)} (${data.total})`;
    renderResults(data.results);
    updatePaginationUI();
  } catch (err) {
    resultsTitle.textContent = filterLabel(filter);
    pagination.hidden = true;
    resultsBody.innerHTML = `<p class="error-state">No se pudo cargar el listado: ${escapeHtml(err.message)}. Revisa que Elasticsearch este corriendo.</p>`;
  } finally {
    scanLine.hidden = true;
  }
}

async function runSearch() {
  const q = qInput.value.trim();
  const onlyLeaks = onlyLeaksInput.checked;

  if (!q && !onlyLeaks) {
    loadList(1, 'all');
    return;
  }

  mode = 'search';
  pagination.hidden = true;
  scanLine.hidden = false;
  try {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (onlyLeaks) params.set('only_leaks', 'true');

    const res = await fetch(`/api/search?${params.toString()}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);

    resultsTitle.textContent = `Resultados (${data.count})`;
    renderResults(data.results);
  } catch (err) {
    resultsTitle.textContent = 'Resultados';
    resultsBody.innerHTML = `<p class="error-state">No se pudo completar la busqueda: ${escapeHtml(err.message)}. Revisa que Elasticsearch este corriendo.</p>`;
  } finally {
    scanLine.hidden = true;
  }
}

function renderServiceTable(openPorts) {
  if (!openPorts || !openPorts.length) {
    return '<p class="detail-block is-empty">Ningun puerto abierto detectado.</p>';
  }
  const rows = openPorts.map((entry) => {
    const [port, protocol] = entry.split('/');
    return `<tr><td>${escapeHtml(port)}</td><td>${escapeHtml(protocol || 'desconocido')}</td></tr>`;
  }).join('');
  return `
    <table class="service-table">
      <thead><tr><th>Puerto</th><th>Protocolo</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderTechList(technologies) {
  if (!technologies || !technologies.length) {
    return '<p class="detail-block is-empty">No se detecto ninguna tecnologia conocida.</p>';
  }
  return technologies.map((t) => `<span class="badge badge--tech">${escapeHtml(t)}</span>`).join(' ');
}

function renderLeaks(doc) {
  const items = [];
  if (doc.tls_cert_sha256) {
    items.push(`
      <dl class="leak-item">
        <dt>Certificado TLS (SHA-256)</dt><dd>${escapeHtml(doc.tls_cert_sha256)}</dd>
        <dt>Subject</dt><dd>${escapeHtml(doc.tls_cert_subject || 'no disponible')}</dd>
        <dt>Issuer</dt><dd>${escapeHtml(doc.tls_cert_issuer || 'no disponible')}</dd>
      </dl>
    `);
  }
  if (doc.jarm_hash) {
    items.push(`
      <dl class="leak-item">
        <dt>JARM (pila/configuracion TLS)</dt><dd>${escapeHtml(doc.jarm_hash)}</dd>
      </dl>
    `);
  }
  if (doc.ssh_fingerprint_sha256) {
    items.push(`
      <dl class="leak-item">
        <dt>Clave SSH (${escapeHtml(doc.ssh_key_type || 'tipo desconocido')})</dt>
        <dd>${escapeHtml(doc.ssh_fingerprint_sha256)}</dd>
      </dl>
    `);
  }
  if (doc.pgp_key_hash) {
    items.push(`
      <dl class="leak-item">
        <dt>Clave PGP publicada (hash)</dt><dd>${escapeHtml(doc.pgp_key_hash)}</dd>
      </dl>
    `);
  }
  if (doc.crypto_addresses && doc.crypto_addresses.length) {
    const rows = doc.crypto_addresses.map((entry) => {
      const [currency, address] = entry.split(/:(.+)/);
      return `<dt>${escapeHtml(currency)}</dt><dd>${escapeHtml(address)}</dd>`;
    }).join('');
    items.push(`
      <dl class="leak-item">
        ${rows}
      </dl>
    `);
  }
  if (doc.html_artifacts && doc.html_artifacts.length) {
    const artifactTypeLabels = { javascript: 'JavaScript', css: 'CSS', favicon: 'Favicon', document: 'Documento' };
    const rows = doc.html_artifacts.map((entry) => {
      const parsed = parseHtmlArtifactEntry(entry);
      const label = artifactTypeLabels[parsed.artifactType] || parsed.artifactType;
      return `<dt>${escapeHtml(label)}${parsed.filename ? ` &mdash; ${escapeHtml(parsed.filename)}` : ''}</dt><dd>${escapeHtml(parsed.hash)}</dd>`;
    }).join('');
    items.push(`
      <dl class="leak-item">
        ${rows}
      </dl>
    `);
  }
  if (!items.length) {
    return '<p class="detail-block is-empty">Ninguna fuga de infraestructura detectada en este dominio.</p>';
  }
  return items.join('');
}

function shortAddr(address) {
  if (!address) return '';
  return address.length > 16 ? `${address.slice(0, 12)}…onion` : address;
}

function parseHtmlArtifactEntry(entry) {
  // Formato guardado: "tipo:hash:url". Se separa por el PRIMER ":" en
  // cada nivel (no por todos), porque la URL puede contener sus propios
  // ":" (ej. "http://dominio.onion/ruta").
  const [artifactType, rest] = entry.split(/:(.+)/);
  const [hash, url] = (rest || '').split(/:(.+)/);
  const filename = url ? url.split('/').filter(Boolean).pop() : null;
  return { artifactType, hash, url: url || null, filename: filename || null };
}

function truncateHash(value, maxLen = 18) {
  // A diferencia de shortAddr, no anade sufijo "...onion": esto se usa
  // para hashes/ids (certificado, JARM, SSH, PGP, direcciones de cripto)
  // que no son direcciones onion, y ese sufijo seria enganoso.
  if (!value) return '';
  return value.length > maxLen ? `${value.slice(0, maxLen)}…` : value;
}

// Etiquetas legibles para las categorias de servicio detectadas por el
// LLM local (config.LLM_CATEGORY_CHOICES). Si aparece una categoria no
// contemplada aqui (por ejemplo si se amplia la lista en config.py sin
// actualizar esto), se muestra el valor crudo tal cual como fallback.
const CATEGORY_LABELS = {
  marketplace: 'Marketplace',
  foro: 'Foro',
  panel_administracion: 'Panel de administracion',
  exchange_cripto: 'Exchange de criptomonedas',
  mensajeria: 'Mensajeria',
  blog_personal: 'Blog personal',
  servicio_tecnico: 'Servicio tecnico',
  directorio_enlaces: 'Directorio de enlaces',
  sin_contenido: 'Sin contenido',
  otro: 'Otro',
};

const RELATION_LABELS = {
  shared_tls_cert: 'certificado TLS compartido',
  shared_ssh_key: 'clave SSH compartida',
  shared_pgp_key: 'clave PGP compartida',
  shared_jarm: 'JARM compartido (misma pila TLS)',
  shared_crypto_address: 'direccion de criptomoneda compartida',
  shared_javascript: 'JavaScript compartido',
  shared_css: 'CSS compartido',
  shared_favicon: 'favicon compartido',
  shared_document: 'documento compartido',
  similar_content: 'contenido similar',
};

// Orden de presentacion: de mayor a menor fuerza de la señal (misma
// jerarquia que usa el backend en find_best_case_study). Todas las
// secciones con datos se muestran siempre, nunca se sustituyen entre si.
const RELATION_ORDER = [
  'shared_tls_cert', 'shared_ssh_key', 'shared_pgp_key',
  'shared_jarm', 'shared_crypto_address',
  'shared_javascript', 'shared_css', 'shared_favicon', 'shared_document',
  'similar_content',
];

function renderRelationTree(rootAddress, relatedFlat) {
  if (!relatedFlat.length) return '';

  const width = 600;
  const rootY = 34;
  const nodeY = 150;
  const spacing = width / (relatedFlat.length + 1);

  let svg = `<svg viewBox="0 0 ${width} 190" class="relation-tree" role="img" aria-label="Arbol de infraestructura relacionada">`;
  relatedFlat.forEach((r, i) => {
    const x = spacing * (i + 1);
    svg += `<line x1="${width / 2}" y1="${rootY + 8}" x2="${x}" y2="${nodeY - 10}" class="tree-edge tree-edge--${r.relation}"></line>`;
  });
  relatedFlat.forEach((r, i) => {
    const x = spacing * (i + 1);
    svg += `
      <g class="tree-node" data-address="${escapeHtml(r.address)}">
        <circle cx="${x}" cy="${nodeY}" r="6" class="tree-node-dot tree-node-dot--${r.relation}"></circle>
        <text x="${x}" y="${nodeY + 20}" text-anchor="middle" class="tree-node-label">${escapeHtml(shortAddr(r.address))}</text>
      </g>
    `;
  });
  svg += `<circle cx="${width / 2}" cy="${rootY}" r="7" class="tree-root-dot"></circle>`;
  svg += `<text x="${width / 2}" y="${rootY - 14}" text-anchor="middle" class="tree-root-label">${escapeHtml(shortAddr(rootAddress))}</text>`;
  svg += `</svg>`;

  const usedRelations = [...new Set(relatedFlat.map((r) => r.relation))];
  const legend = usedRelations.map((rel) => `
    <span style="color: ${rel === 'shared_tls_cert' ? 'var(--signal)' : rel === 'shared_ssh_key' ? 'var(--amber)' : 'var(--steel)'}">
      <span class="legend-swatch"></span>${escapeHtml(RELATION_LABELS[rel] || rel)}
    </span>
  `).join('');

  return `${svg}<div class="relation-legend">${legend}</div>`;
}

// Mapea cada tipo de relacion al campo booleano del documento indexado
// que indica si el dominio TIENE ese dato extraido (independientemente
// de si coincide con otro dominio o no). similar_content no tiene un
// booleano propio (no es una fuga "declarada", es una comparacion a
// posteriori), asi que ese apartado solo se muestra si hay coincidencias.
const RELATION_LEAK_FIELD = {
  shared_tls_cert: 'has_tls_cert',
  shared_ssh_key: 'has_ssh_key',
  shared_jarm: 'has_jarm',
  shared_pgp_key: 'has_pgp_key',
  shared_crypto_address: 'has_crypto_address',
  shared_javascript: 'has_javascript',
  shared_css: 'has_css',
  shared_favicon: 'has_favicon',
  shared_document: 'has_document',
};

const ARTIFACT_SECTION_TYPE = {
  shared_javascript: 'javascript',
  shared_css: 'css',
  shared_favicon: 'favicon',
  shared_document: 'document',
};

function findSectionFilenames(doc, type, items) {
  const artifactType = ARTIFACT_SECTION_TYPE[type];
  if (!artifactType || !doc.html_artifacts) return [];
  // Con coincidencias: solo los ficheros que de verdad se comparten con
  // otro dominio. Sin coincidencias: todos los ficheros de ese tipo que
  // se comprobaron en este dominio (para que se vea QUE se comprobo).
  const hashesInSection = items.length ? new Set(items.map((r) => r.via).filter(Boolean)) : null;
  const filenames = new Set();
  doc.html_artifacts.forEach((entry) => {
    const parsed = parseHtmlArtifactEntry(entry);
    if (parsed.artifactType !== artifactType || !parsed.filename) return;
    if (hashesInSection && !hashesInSection.has(parsed.hash)) return;
    filenames.add(parsed.filename);
  });
  return [...filenames];
}

// Mismo umbral que src/correlation.py usa para avisar de grupos
// sospechosamente genericos (>50 dominios comparten el mismo valor):
// grupo pequeño = señal fuerte (dificil que coincida por azar), grupo
// grande = probablemente una configuracion/artefacto por defecto, no
// evidencia de operador compartido. Ver docs/DECISIONS.md.
const GENERIC_GROUP_THRESHOLD = 50;

function renderGroupSizeBadge(groupSize) {
  // similar_content es una relacion directa par a par, no un grupo con
  // nodo compartido - el concepto de "tamaño de grupo" no aplica.
  if (groupSize === null || groupSize === undefined) return '';
  const isGeneric = groupSize > GENERIC_GROUP_THRESHOLD;
  const cls = isGeneric ? 'group-size-badge group-size-badge--weak' : 'group-size-badge';
  const tooltip = isGeneric
    ? `${groupSize} dominios en total comparten este mismo valor - probablemente un artefacto generico, no evidencia de operador compartido.`
    : `${groupSize} dominios en total comparten este mismo valor.`;
  return `<span class="${cls}" title="${escapeHtml(tooltip)}">(${groupSize})</span>`;
}

function renderRelationSections(relatedGrouped, doc, activeType = 'all') {
  let typesToShow = RELATION_ORDER.filter((type) => {
    const items = relatedGrouped[type] || [];
    if (type === 'similar_content') return items.length > 0;
    const leakField = RELATION_LEAK_FIELD[type];
    return leakField ? Boolean(doc[leakField]) : items.length > 0;
  });
  if (activeType !== 'all') {
    typesToShow = typesToShow.filter((type) => type === activeType);
  }

  if (!typesToShow.length) {
    return '<p class="detail-block is-empty">Este dominio no tiene ninguna fuga de infraestructura extraida todavia.</p>';
  }

  return typesToShow.map((type) => {
    const items = relatedGrouped[type] || [];
    const title = RELATION_LABELS[type] || type;
    const filenames = findSectionFilenames(doc, type, items);
    const filenameSuffix = filenames.length
      ? ` <span class="relation-section-filename">&mdash; ${filenames.map(escapeHtml).join(', ')}</span>`
      : '';

    if (!items.length) {
      return `
        <div class="relation-section">
          <h4 class="relation-section-title">${escapeHtml(title)}${filenameSuffix} <span class="relation-section-count relation-section-count--none">(0)</span></h4>
          <p class="detail-block is-empty">Sin coincidencias con otro dominio del dataset.</p>
        </div>
      `;
    }

    const rows = items.map((r) => `
      <div class="relation-list-item">
        <span>${escapeHtml(r.address)}</span>
        ${renderGroupSizeBadge(r.group_size)}
        <button type="button" class="drill-btn" data-address="${escapeHtml(r.address)}">Ver ficha</button>
      </div>
    `).join('');
    return `
      <div class="relation-section">
        <h4 class="relation-section-title">${escapeHtml(title)}${filenameSuffix} <span class="relation-section-count">(${items.length})</span></h4>
        ${rows}
      </div>
    `;
  }).join('');
}

function flattenRelated(relatedGrouped) {
  return RELATION_ORDER.flatMap((type) => relatedGrouped[type] || []);
}

async function loadRelated(address) {
  try {
    const res = await fetch(`/api/related/${encodeURIComponent(address)}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    return data.related || {};
  } catch (err) {
    document.getElementById('detail-related-tree').innerHTML =
      `<p class="error-state">No se pudo consultar el grafo de infraestructura: ${escapeHtml(err.message)}. Revisa que Neo4j este corriendo.</p>`;
    document.getElementById('detail-related-list').innerHTML = '';
    return null;
  }
}

function getTypesWithData(grouped) {
  return RELATION_ORDER.filter((t) => (grouped[t] || []).length > 0);
}

function getFilteredFlat(grouped, activeType) {
  if (activeType === 'all') return flattenRelated(grouped);
  return grouped[activeType] || [];
}

function renderTabs(container, grouped, activeType, onSelect) {
  const types = getTypesWithData(grouped);
  if (types.length === 0) {
    // Nada que filtrar de verdad (ni una sola relacion encontrada): aqui
    // si tiene sentido no mostrar pestañas.
    container.innerHTML = '';
    return;
  }
  const buttons = [{ type: 'all', label: 'Todos' }, ...types.map((t) => ({ type: t, label: RELATION_LABELS[t] || t }))];
  container.innerHTML = buttons.map((b) => `
    <button type="button" class="relation-tab ${activeType === b.type ? 'is-active' : ''}" data-type="${b.type}">${escapeHtml(b.label)}</button>
  `).join('');
  container.querySelectorAll('.relation-tab').forEach((btn) => {
    btn.addEventListener('click', () => onSelect(btn.dataset.type));
  });
}

function computeActiveLabelText(grouped, doc, activeType) {
  const items = activeType === 'all' ? flattenRelated(grouped) : (grouped[activeType] || []);
  const count = items.length;
  const countText = `${count} ${count === 1 ? 'dominio' : 'dominios'} mostrado${count === 1 ? '' : 's'}`;

  if (activeType === 'all') return countText;

  const filenames = findSectionFilenames(doc, activeType, items);
  const title = RELATION_LABELS[activeType] || activeType;
  const filenameSuffix = filenames.length ? ` — ${filenames.join(', ')}` : '';
  return `${title}${filenameSuffix} · ${countText}`;
}

function refreshCompactTabs() {
  renderTabs(relationTabsEl, relationState.grouped, relationState.activeType, (type) => {
    relationState.activeType = type;
    refreshCompactTabs();
    refreshCompactTree();
  });
}

function refreshCompactTree() {
  const flat = getFilteredFlat(relationState.grouped, relationState.activeType);
  document.getElementById('detail-related-tree').innerHTML = renderRelationTree(relationState.address, flat);
  attachDrillHandlers(document.getElementById('detail-related-tree'));
  relationActiveLabel.textContent = computeActiveLabelText(relationState.grouped, relationState.doc, relationState.activeType);
  refreshCompactList();
}

function refreshCompactList() {
  const listEl = document.getElementById('detail-related-list');
  listEl.innerHTML = renderRelationSections(relationState.grouped, relationState.doc, relationState.activeType);
  listEl.querySelectorAll('.drill-btn').forEach((el) => {
    el.addEventListener('click', () => {
      const target = el.dataset.address;
      if (target) openDetailByAddress(target);
    });
  });
}

function attachDrillHandlers(scopeEl) {
  scopeEl.querySelectorAll('.tree-node').forEach((el) => {
    el.addEventListener('click', () => {
      const target = el.dataset.address;
      if (target) { closeRelationModal(); openDetailByAddress(target); }
    });
  });
}

// ---------- Vista ampliada: layout radial + zoom/pan ----------

function buildRadialTreeSvg(rootAddress, relatedFlat) {
  const size = 900;
  const cx = size / 2;
  const cy = size / 2;
  const n = relatedFlat.length;
  if (!n) {
    return `<svg viewBox="0 0 ${size} ${size}"><circle cx="${cx}" cy="${cy}" r="12" class="tree-root-dot"></circle><text x="${cx}" y="${cy - 20}" text-anchor="middle" class="tree-root-label">${escapeHtml(shortAddr(rootAddress))}</text></svg>`;
  }
  const radius = Math.max(200, Math.min(400, 60 + n * 5));

  let svg = `<svg viewBox="0 0 ${size} ${size}">`;
  relatedFlat.forEach((r, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    svg += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" class="tree-edge tree-edge--${r.relation}"></line>`;
  });
  relatedFlat.forEach((r, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    const cos = Math.cos(angle);
    const anchor = cos > 0.15 ? 'start' : cos < -0.15 ? 'end' : 'middle';
    const dx = cos > 0.15 ? 12 : cos < -0.15 ? -12 : 0;
    svg += `
      <g class="tree-node" data-address="${escapeHtml(r.address)}">
        <circle cx="${x}" cy="${y}" r="9" class="tree-node-dot tree-node-dot--${r.relation}"></circle>
        <text x="${x + dx}" y="${y + 4}" text-anchor="${anchor}" class="tree-node-label">${escapeHtml(shortAddr(r.address))}</text>
      </g>
    `;
  });
  svg += `<circle cx="${cx}" cy="${cy}" r="13" class="tree-root-dot"></circle>`;
  svg += `<text x="${cx}" y="${cy - 22}" text-anchor="middle" class="tree-root-label">${escapeHtml(shortAddr(rootAddress))}</text>`;
  svg += `</svg>`;
  return svg;
}

function attachZoomPan(svgEl) {
  const initial = { x: 0, y: 0, w: 900, h: 900 };
  let box = { ...initial };
  const apply = () => svgEl.setAttribute('viewBox', `${box.x} ${box.y} ${box.w} ${box.h}`);
  apply();

  svgEl.addEventListener('wheel', (e) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.1 : 0.9;
    const rect = svgEl.getBoundingClientRect();
    const mx = (e.clientX - rect.left) / rect.width;
    const my = (e.clientY - rect.top) / rect.height;
    const newW = Math.max(120, Math.min(initial.w * 4, box.w * factor));
    const newH = Math.max(120, Math.min(initial.h * 4, box.h * factor));
    box.x += (box.w - newW) * mx;
    box.y += (box.h - newH) * my;
    box.w = newW;
    box.h = newH;
    apply();
  }, { passive: false });

  let dragging = false;
  let lastX = 0;
  let lastY = 0;
  const canvas = svgEl.parentElement;
  svgEl.addEventListener('mousedown', (e) => {
    dragging = true;
    lastX = e.clientX;
    lastY = e.clientY;
    canvas.classList.add('is-dragging');
  });
  window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const rect = svgEl.getBoundingClientRect();
    box.x -= (e.clientX - lastX) * (box.w / rect.width);
    box.y -= (e.clientY - lastY) * (box.h / rect.height);
    lastX = e.clientX;
    lastY = e.clientY;
    apply();
  });
  window.addEventListener('mouseup', () => {
    dragging = false;
    canvas.classList.remove('is-dragging');
  });
}

function buildNeo4jQuery(rootAddress, relatedFlat) {
  const addresses = [rootAddress, ...new Set(relatedFlat.map((r) => r.address))];
  const literal = addresses.map((a) => `"${a}"`).join(', ');
  return `MATCH (o:Onion) WHERE o.address IN [${literal}]\nOPTIONAL MATCH (o)-[r]-(x)\nRETURN o, r, x`;
}

function renderModalTree() {
  const flat = getFilteredFlat(relationState.grouped, relationState.modalActiveType);
  relationModalCanvas.innerHTML = buildRadialTreeSvg(relationState.address, flat);
  attachDrillHandlers(relationModalCanvas);
  const svgEl = relationModalCanvas.querySelector('svg');
  if (svgEl) attachZoomPan(svgEl);
  relationNeo4jQuery.textContent = buildNeo4jQuery(relationState.address, flat);
  relationModalActiveLabel.textContent = computeActiveLabelText(relationState.grouped, relationState.doc, relationState.modalActiveType);
}

function refreshModalTabs() {
  renderTabs(relationModalTabsEl, relationState.grouped, relationState.modalActiveType, (type) => {
    relationState.modalActiveType = type;
    refreshModalTabs();
    renderModalTree();
    // Se reconstruye la escena 3D al cambiar de pestaña, igual que la
    // vista 2D. Antes esto se evitaba a proposito (para no reconstruir
    // en cada clic, sospechando que cada reconstruccion contribuia a la
    // fuga de memoria), pero con el limite duro de MAX_3D_NODES cada
    // reconstruccion esta acotada a un maximo razonable de nodos, asi
    // que ya no es una operacion cara aunque se repita en cada clic - y
    // sin esto, cambiar de pestaña en 3D no tenia ningun efecto visible
    // hasta pulsar "Vista 3D" de nuevo, lo cual se percibia como un
    // fallo (con razon: no era intuitivo).
    if (relationState.viewMode === '3d') render3DModalView();
  });
}

function setRelationViewMode(mode) {
  relationState.viewMode = mode;
  relationViewModeToggle.querySelectorAll('.view-mode-btn').forEach((btn) => {
    btn.classList.toggle('is-active', btn.dataset.mode === mode);
  });
  relationModalCanvas.hidden = mode !== '2d';
  relationModalCanvas3dWrap.hidden = mode !== '3d';
  relation3dResetBtn.hidden = mode !== '3d';
  relationModalHintEl.textContent = mode === '3d'
    ? 'Arrastra un nodo para fijarlo \u00b7 rueda para zoom \u00b7 clic para ver su ficha'
    : 'Rueda del raton para zoom \u00b7 arrastra para desplazarte';

  if (mode === '3d') {
    render3DModalView();
  } else {
    // Al volver a 2D, no dejar la escena WebGL corriendo oculta de fondo.
    disposeGraph3DInstance();
  }
}

relationViewModeToggle.querySelectorAll('.view-mode-btn').forEach((btn) => {
  btn.addEventListener('click', () => setRelationViewMode(btn.dataset.mode));
});

// Pantalla completa sobre el PANEL entero (no solo el lienzo), para
// seguir teniendo acceso a las pestañas, el interruptor 2D/3D y el
// boton de reiniciar posiciones mientras se explora a tamaño completo.
function toggleRelationFullscreen() {
  const panel = document.querySelector('.relation-modal-panel');
  if (!document.fullscreenElement) {
    panel.requestFullscreen().catch(() => {
      relationFullscreenBtn.textContent = '\u2715 Pantalla completa no disponible';
      setTimeout(() => { relationFullscreenBtn.textContent = '\u2732 Pantalla completa'; }, 1500);
    });
  } else {
    document.exitFullscreen();
  }
}

relationFullscreenBtn.addEventListener('click', toggleRelationFullscreen);
document.addEventListener('fullscreenchange', () => {
  relationFullscreenBtn.textContent = document.fullscreenElement ? '\u2715 Salir de pantalla completa' : '\u2732 Pantalla completa';
  // El cambio de tamaño al entrar/salir de pantalla completa lo recoge
  // el ResizeObserver del lienzo 3D automaticamente; para la vista 2D
  // (SVG con viewBox) no hace falta ningun ajuste, se adapta sola.
});

function openRelationModal() {
  relationState.modalActiveType = relationState.activeType;
  relationModalAddress.textContent = relationState.address;
  refreshModalTabs();
  renderModalTree();
  setRelationViewMode('2d'); // la vista 3D se queda como opcion, nunca por defecto (mas pesada de cargar)
  relationModalOverlay.hidden = false;
}

function closeRelationModal() {
  relationModalOverlay.hidden = true;
  relation3dNodePanel.hidden = true;
  disposeGraph3DInstance();
}

relationExpandBtn.addEventListener('click', openRelationModal);

// ---------- Vista 3D (opcional, carga diferida) ----------

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Colores por tipo de relacion para la vista 3D. Reutiliza la paleta del
// proyecto (variables CSS) donde ya existe un color asignado en el arbol
// 2D (certificado/SSH); el resto de tipos (JARM, PGP, cripto, artefactos
// HTML) no tenian color propio en el 2D (usaban el gris generico), asi
// que aqui se les da uno distinto solo para diferenciarlos visualmente
// mejor en 3D - no implica ningun cambio de significado ni de prioridad.
function relation3DColors() {
  return {
    shared_tls_cert: cssVar('--signal'),
    shared_ssh_key: cssVar('--amber'),
    shared_jarm: '#8AA0C4',
    shared_pgp_key: '#C77DFF',
    shared_crypto_address: '#FFB86B',
    shared_javascript: '#6FCF97',
    shared_css: '#56CCF2',
    shared_favicon: '#F2C94C',
    shared_document: '#EB5757',
    similar_content: cssVar('--steel'),
  };
}

// Misma jerarquia de fiabilidad que usa find_best_case_study() en el
// backend (certificado/SSH/PGP = identidad exacta; JARM/cripto = fuerte
// pero menos concluyente). Los artefactos HTML y la similitud de
// contenido todavia no tienen un nivel asignado en el backend, asi que
// aqui tampoco se les pone anillo (no inventamos una jerarquia que el
// resto del proyecto no comparte).
const TIER_3D_BY_RELATION = {
  shared_tls_cert: 1, shared_ssh_key: 1, shared_pgp_key: 1,
  shared_jarm: 2, shared_crypto_address: 2,
};
const TIER_3D_RING_COLORS = { 1: '#FFD54A', 2: '#C7CFDD' };

let threeDLibsPromise = null;
function attemptLoadThreeDLibs() {
  return new Promise((resolve, reject) => {
    const scripts = [
      'https://cdnjs.cloudflare.com/ajax/libs/three.js/0.149.0/three.min.js',
      'https://unpkg.com/three-spritetext@1.9.3/dist/three-spritetext.min.js',
      'https://unpkg.com/3d-force-graph@1.71.3/dist/3d-force-graph.min.js',
    ];
    let loaded = 0;
    scripts.forEach((src) => {
      const el = document.createElement('script');
      el.src = src;
      el.onload = () => {
        loaded += 1;
        if (loaded === scripts.length) {
          // Verificacion explicita: un script puede responder 200 (onload
          // dispara) y aun asi no dejar disponible lo esperado, por
          // ejemplo si un bloqueador de anuncios/extension del navegador
          // (Brave Shields incluido) sustituye su contenido por uno vacio
          // en vez de bloquear la peticion por completo. Sin esta
          // comprobacion, el fallo aparece mas tarde como un
          // "ReferenceError" críptico en la consola en vez de un aviso
          // claro en pantalla.
          if (typeof THREE === 'undefined' || typeof SpriteText === 'undefined' || typeof ForceGraph3D === 'undefined') {
            reject(new Error(
              'Las librerias 3D se descargaron pero no se inicializaron correctamente '
              + '(revisa si un bloqueador de anuncios o extension del navegador -Brave Shields incluido- '
              + 'esta interceptando unpkg.com/cdnjs.cloudflare.com para esta pagina)'
            ));
            return;
          }
          resolve();
        }
      };
      el.onerror = () => reject(new Error(`No se pudo cargar ${src}`));
      document.head.appendChild(el);
      // El script fallido (o su reemplazo bloqueado) se queda en el DOM;
      // en un reintento se añade OTRO <script> con el mismo src - los
      // navegadores permiten cargar el mismo src varias veces sin
      // problema, cada <script> es una peticion independiente.
    });
  });
}

async function loadThreeDLibs() {
  if (threeDLibsPromise) return threeDLibsPromise;
  const promise = (async () => {
    const maxAttempts = 3;
    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await attemptLoadThreeDLibs();
        return; // exito, no hace falta reintentar
      } catch (err) {
        lastError = err;
        // Fallo transitorio (visto en la practica: falla la primera vez,
        // funciona la segunda) - se reintenta un par de veces mas antes
        // de rendirse y mostrar el error al usuario.
        await new Promise((r) => setTimeout(r, 400));
      }
    }
    throw lastError;
  })();
  // Solo se guarda en cache si tiene exito: un fallo (ej. bloqueado por
  // una extension) no debe dejar la carga "envenenada" para el resto de
  // la sesion - el usuario podria solucionar el bloqueo y reintentar
  // pulsando "Vista 3D" otra vez, sin necesitar recargar la pagina.
  promise.catch(() => { threeDLibsPromise = null; });
  threeDLibsPromise = promise;
  return threeDLibsPromise;
}

function build3DHoverCard(n) {
  if (n.root) {
    const doc = relationState.doc || {};
    const ports = (doc.open_ports && doc.open_ports.length) ? doc.open_ports.join(', ') : 'ninguno detectado';
    const title = doc.http_title || 'Sin titulo HTTP disponible';
    return `
      <div class="node-3d-card">
        <div class="node-3d-card-address">\u2605 ${escapeHtml(n.id)}</div>
        <div class="node-3d-card-row"><span class="node-3d-card-label">Rol</span><span>Dominio raiz</span></div>
        <div class="node-3d-card-row"><span class="node-3d-card-label">Titulo</span><span>${escapeHtml(title)}</span></div>
        <div class="node-3d-card-row"><span class="node-3d-card-label">Puertos</span><span>${escapeHtml(ports)}</span></div>
      </div>
    `;
  }
  const relationRows = (n.relations || []).map((r) =>
    `<div class="node-3d-card-relation">&bull; ${escapeHtml(RELATION_LABELS[r.type] || r.type)}${renderGroupSizeBadge(r.groupSize)}</div>`
  ).join('') || '<div class="node-3d-card-relation is-empty">sin relacion directa con la raiz</div>';
  return `
    <div class="node-3d-card">
      <div class="node-3d-card-address">${escapeHtml(n.id)}</div>
      <div class="node-3d-card-section-label">Relacion con el dominio raiz</div>
      ${relationRows}
      <div class="node-3d-card-hint">clic para ver detalle completo</div>
    </div>
  `;
}

function shortLabel3D(address) {
  return address.length > 14 ? `${address.slice(0, 10)}\u2026onion` : address;
}

// Limite duro de nodos renderizados en 3D. Un grupo de cientos o miles
// de dominios compartiendo un mismo artefacto (ej. una libreria
// JavaScript muy comun tipo jQuery) es casi siempre el mismo caso que
// ya senalamos en el backend como "artefacto generico, no distintivo"
// (ver el aviso de grupos >50 en correlate()) - no aporta mas
// informacion visualizar 971 nodos que 80, y renderizar y simular
// fisicamente esa cantidad de objetos 3D a la vez es una carga real
// para cualquier equipo, no solo uno modesto.
const MAX_3D_NODES = 80;

function build3DGraphData(rootAddress, flat) {
  const capped = flat.slice(0, MAX_3D_NODES);
  const nodes = [{ id: rootAddress, root: true }];
  const links = [];
  capped.forEach((r) => {
    if (!nodes.some((n) => n.id === r.address)) {
      nodes.push({ id: r.address, root: false, relations: [{ type: r.relation, via: r.via, groupSize: r.group_size }] });
    } else {
      nodes.find((n) => n.id === r.address).relations.push({ type: r.relation, via: r.via, groupSize: r.group_size });
    }
    links.push({ source: rootAddress, target: r.address, relation: r.relation });
  });
  return { nodes, links, truncated: flat.length > MAX_3D_NODES, totalAvailable: flat.length };
}

let graph3DInstance = null;

function disposeGraph3DInstance() {
  // Sin esto, cada vez que se reconstruye el grafo (cambio de pestaña
  // estando en 3D, "Reiniciar posiciones", volver a abrir la vista 3D)
  // la escena WebGL anterior sigue corriendo en segundo plano - su
  // bucle de animacion no se detiene solo porque se quite el canvas del
  // DOM. Con cada interaccion se iba acumulando una escena mas,
  // explicando una subida sostenida de RAM/CPU cuanto mas se usaba la
  // vista 3D en la misma sesion. Los metodos se llaman de forma
  // defensiva (try/catch) porque no todas las versiones de la libreria
  // exponen exactamente los mismos metodos de limpieza.
  if (!graph3DInstance) return;
  try { graph3DInstance.pauseAnimation(); } catch { /* metodo no disponible en esta version */ }

  // CRITICO, y lo que realmente faltaba: en Three.js, ni quitar objetos
  // de la escena ni liberar el renderer (mas abajo) libera
  // automaticamente las geometrias/materiales/texturas de CADA objeto.
  // Hay que recorrer la escena y llamar a .dispose() en cada uno, a
  // mano. Con 65+ nodos, cada uno con 2-3 formas geometricas propias
  // (esfera, halo, anillo) mas la textura de canvas de su etiqueta de
  // texto (SpriteText), cada reconstruccion del grafo dejaba todo eso
  // abandonado en memoria de la GPU sin que nadie lo reclamara - esta
  // es la causa mas tipica de fugas reales en aplicaciones Three.js.
  try {
    const scene = graph3DInstance.scene && graph3DInstance.scene();
    if (scene) {
      scene.traverse((obj) => {
        if (obj.geometry) obj.geometry.dispose();
        if (obj.material) {
          const materials = Array.isArray(obj.material) ? obj.material : [obj.material];
          materials.forEach((mat) => {
            if (mat.map) mat.map.dispose(); // textura de canvas de SpriteText, entre otras
            mat.dispose();
          });
        }
      });
      while (scene.children.length > 0) scene.remove(scene.children[0]);
    }
  } catch { /* metodo no disponible en esta version */ }

  try {
    const renderer = graph3DInstance.renderer && graph3DInstance.renderer();
    if (renderer) {
      renderer.dispose();
      // dispose() libera buffers/texturas/geometrias, pero NO garantiza
      // que el navegador libere el contexto WebGL en si de inmediato.
      // forceContextLoss() es la forma recomendada (documentada por
      // Three.js) de asegurar que el contexto se libera de verdad, no
      // solo sus recursos internos - importante porque los navegadores
      // limitan cuantos contextos WebGL simultaneos permiten, y sin
      // esto podian quedar "vivos" de fondo aunque dispose() ya se
      // hubiera llamado.
      if (renderer.forceContextLoss) renderer.forceContextLoss();
    }
  } catch { /* metodo no disponible en esta version */ }
  try { graph3DInstance._destructor && graph3DInstance._destructor(); } catch { /* metodo no disponible en esta version */ }

  if (relation3DResizeObserver) {
    relation3DResizeObserver.disconnect();
    relation3DResizeObserver = null;
  }

  graph3DInstance = null;
}

async function render3DModalView() {
  relation3dNodePanel.hidden = true;
  relationModalCanvas3d.innerHTML = '<p class="relation-3d-status">Cargando motor 3D&hellip;</p>';
  try {
    await loadThreeDLibs();
  } catch (err) {
    relationModalCanvas3d.innerHTML = `<p class="relation-3d-status is-error">No se pudo cargar la vista 3D (${escapeHtml(err.message)}). Revisa tu conexion a internet - esta vista carga una libreria externa via CDN, a diferencia del resto del dashboard.</p>`;
    return;
  }

  const flat = getFilteredFlat(relationState.grouped, relationState.modalActiveType);
  const colors = relation3DColors();
  const data = build3DGraphData(relationState.address, flat);

  // Aviso claro cuando el limite duro de nodos (MAX_3D_NODES) ha
  // recortado el conjunto real: no es una sugerencia, es lo que
  // realmente esta pasando en pantalla - el usuario debe saber que no
  // esta viendo el total.
  relationModalHintEl.textContent = data.truncated
    ? `Mostrando ${MAX_3D_NODES} de ${data.totalAvailable} nodos (limite de la vista 3D) \u00b7 usa la Vista 2D o Neo4j Browser para el conjunto completo`
    : `Mostrando ${data.totalAvailable} nodos \u00b7 arrastra un nodo para fijarlo \u00b7 rueda para zoom \u00b7 clic para ver su ficha`;

  disposeGraph3DInstance();
  relationModalCanvas3d.innerHTML = '';
  // Fuerza un reflow sincrono antes de construir el grafo: si el
  // contenedor acaba de pasar de oculto a visible (o venimos de un
  // "loadThreeDLibs()" ya cacheado que resuelve casi al instante, sin
  // ceder tiempo al navegador para recalcular el layout), la libreria
  // podria leer un ancho/alto obsoleto (0 o el de la ultima vez que fue
  // visible) al construirse, dejando el grafo pequeño y mal posicionado
  // en una esquina en vez de centrado y a tamaño completo.
  void relationModalCanvas3d.offsetHeight;

  const nodeRadius = (n) => (n.root ? 7 : 3.5);
  const bestTier3D = (n) => {
    if (!n.relations || !n.relations.length) return null;
    const tiers = n.relations.map((r) => TIER_3D_BY_RELATION[r.type]).filter(Boolean);
    return tiers.length ? Math.min(...tiers) : null;
  };

  graph3DInstance = ForceGraph3D()(relationModalCanvas3d)
    .graphData(data)
    .backgroundColor(cssVar('--ink'))
    // Acota el motor de fisica: sin esto, cada vez que se arrastra un
    // nodo (o se cambia de pestaña, reconstruyendo el grafo) la
    // simulacion puede seguir recalculando posiciones durante mucho
    // tiempo antes de "enfriarse" del todo, consumiendo CPU de forma
    // sostenida. Con un limite de ticks, el peor caso de coste de la
    // fisica queda acotado independientemente de cuantos nodos haya.
    .cooldownTicks(80)
    .nodeLabel((n) => build3DHoverCard(n))
    .nodeVal(nodeRadius)
    .nodeThreeObject((n) => {
      const group = new THREE.Group();

      // Esfera invisible mas grande, solo para ampliar la zona que
      // registra el clic. La etiqueta de texto flota POR ENCIMA de la
      // esfera visible - apuntar al texto (lo mas legible, lo natural
      // al hacer clic) podia caer fuera de la zona real detectada,
      // haciendo que el clic pareciera no funcionar "a veces". Esta
      // esfera no se ve (opacity 0) pero si cuenta para el clic.
      group.add(new THREE.Mesh(
        new THREE.SphereGeometry(nodeRadius(n) * 2.5, 8, 8),
        new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false }),
      ));

      // Segmentos reducidos deliberadamente (8 en vez de 16, por
      // ejemplo): con esferas tan pequeñas en pantalla, la diferencia
      // visual es minima, pero el numero de triangulos que la GPU tiene
      // que procesar en cada fotograma baja mucho - multiplicado por
      // decenas de nodos a la vez, es una de las optimizaciones con
      // mejor relacion beneficio/coste en una escena asi.
      if (n.root) {
        group.add(new THREE.Mesh(
          new THREE.SphereGeometry(nodeRadius(n) * 2, 12, 12),
          new THREE.MeshBasicMaterial({ color: cssVar('--signal'), transparent: true, opacity: 0.05 }),
        ));
      }
      const color = n.root ? cssVar('--paper') : (colors[(n.relations && n.relations[0] || {}).type] || cssVar('--steel'));
      group.add(new THREE.Mesh(
        new THREE.SphereGeometry(nodeRadius(n), 8, 8),
        new THREE.MeshLambertMaterial({ color }),
      ));
      if (!n.root) {
        const tier = bestTier3D(n);
        if (tier) {
          group.add(new THREE.Mesh(
            new THREE.TorusGeometry(nodeRadius(n) * 1.5, 0.3, 6, 16),
            new THREE.MeshBasicMaterial({ color: TIER_3D_RING_COLORS[tier], transparent: true, opacity: 0.85 }),
          ));
        }
      }
      const label = new SpriteText(n.root ? `\u2605 ${shortLabel3D(n.id)}` : shortLabel3D(n.id));
      label.textHeight = n.root ? 3.2 : 1.8;
      label.color = n.root ? cssVar('--paper') : '#9AAAC6';
      label.fontFace = 'JetBrains Mono, monospace';
      if (n.root) { label.backgroundColor = 'rgba(18,26,46,0.85)'; label.padding = 2; }
      label.position.set(0, nodeRadius(n) + (n.root ? 6 : 3.2), 0);
      group.add(label);
      return group;
    })
    .linkColor((l) => colors[l.relation] || cssVar('--steel'))
    .linkOpacity(0.5)
    .linkWidth(1.1)
    .onNodeDragEnd((n) => { n.fx = n.x; n.fy = n.y; n.fz = n.z; })
    .onNodeClick((n) => { populate3DNodePanel(n.id, Boolean(n.root)); });

  // Sincroniza el tamaño explicitamente con el del contenedor real: no
  // fiarse solo de la deteccion automatica de la libreria al construirse
  // (ver comentario del reflow forzado mas arriba).
  graph3DInstance.width(relationModalCanvas3d.clientWidth);
  graph3DInstance.height(relationModalCanvas3d.clientHeight);

  // Limitar la densidad de pixeles de renderizado: por defecto se usa
  // window.devicePixelRatio, que en pantallas de alta densidad (2x, 3x)
  // multiplica el trabajo de la GPU por 4x o 9x sin aportar una mejora
  // perceptible en un grafo de nodos/lineas como este. Esta es
  // probablemente la fuente de carga mas facil de pasar por alto en
  // cualquier escena WebGL, y una de las optimizaciones estandar mas
  // recomendadas para Three.js en equipos modestos.
  try {
    const renderer = graph3DInstance.renderer && graph3DInstance.renderer();
    if (renderer && renderer.setPixelRatio) renderer.setPixelRatio(1);
  } catch { /* metodo no disponible en esta version */ }

  attach3DResizeObserver();
}

let relation3DResizeObserver = null;
function attach3DResizeObserver() {
  if (relation3DResizeObserver) relation3DResizeObserver.disconnect();
  relation3DResizeObserver = new ResizeObserver(() => {
    if (graph3DInstance && relationState.viewMode === '3d') {
      graph3DInstance.width(relationModalCanvas3d.clientWidth);
      graph3DInstance.height(relationModalCanvas3d.clientHeight);
    }
  });
  relation3DResizeObserver.observe(relationModalCanvas3d);
}

function ownLeakBadgesFor(doc) {
  const map = {
    has_tls_cert: 'TLS', has_jarm: 'JARM', has_ssh_key: 'SSH', has_pgp_key: 'PGP',
    has_crypto_address: 'CRIPTO', has_javascript: 'JS', has_css: 'CSS',
    has_favicon: 'FAVICON', has_document: 'DOC',
  };
  return Object.entries(map).filter(([field]) => doc[field]).map(([, label]) => label);
}

async function populate3DNodePanel(address, isRoot) {
  relation3dNodePanel.hidden = false;
  document.getElementById('relation-3d-node-panel-eyebrow').textContent = isRoot ? 'Dominio raiz' : 'Nodo seleccionado';
  relation3dNodePanelAddress.textContent = address;
  relation3dNodePanelBody.innerHTML = '<dt>Cargando</dt><dd class="is-empty">Consultando su ficha&hellip;</dd>';
  relation3dNodePanelFullBtn.onclick = () => { closeRelationModal(); openDetailByAddress(address); };

  await ensureDocLoaded(address);
  const doc = docsByAddress[address] || { address, status: 'desconocido' };

  const ports = (doc.open_ports && doc.open_ports.length) ? doc.open_ports.join(', ') : 'ninguno detectado';
  const tech = (doc.technologies && doc.technologies.length) ? doc.technologies.join(', ') : 'sin tecnologia detectada';
  const title = doc.http_title || 'Sin titulo HTTP disponible';
  const badges = ownLeakBadgesFor(doc);
  const badgesHtml = badges.length
    ? badges.map((b) => `<span class="badge badge--leak">${escapeHtml(b)}</span>`).join(' ')
    : '<span class="is-empty">sin fugas propias detectadas</span>';

  relation3dNodePanelBody.innerHTML = `
    <dt>Estado</dt><dd>${escapeHtml(doc.status || 'desconocido')}</dd>
    <dt>Titulo de la pagina</dt><dd>${escapeHtml(title)}</dd>
    <dt>Puertos abiertos</dt><dd>${escapeHtml(ports)}</dd>
    <dt>Tecnologia</dt><dd>${escapeHtml(tech)}</dd>
    <dt>Fugas propias</dt><dd>${badgesHtml}</dd>
  `;
}

relation3dNodePanelClose.addEventListener('click', () => { relation3dNodePanel.hidden = true; });

relation3dResetBtn.addEventListener('click', () => {
  if (relationState.viewMode !== '3d' || !graph3DInstance) return;
  // Antes esto llamaba a render3DModalView(), reconstruyendo la escena
  // WebGL entera - exactamente la operacion que sospechamos que arrastra
  // la fuga de memoria (oyentes de eventos de la libreria que no se
  // desenganchan bien entre instancias). Ahora se hace "in-place": se
  // despegan los nodos fijados de la MISMA instancia ya construida y se
  // reactiva la simulacion fisica, sin crear una escena nueva.
  try {
    const gd = graph3DInstance.graphData();
    gd.nodes.forEach((n) => { delete n.fx; delete n.fy; delete n.fz; });
    if (graph3DInstance.d3ReheatSimulation) graph3DInstance.d3ReheatSimulation();
  } catch { /* si algo falla aqui, no merece la pena arriesgar una reconstruccion completa */ }
});
relationModalClose.addEventListener('click', closeRelationModal);
relationModalOverlay.addEventListener('click', (e) => { if (e.target === relationModalOverlay) closeRelationModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !relationModalOverlay.hidden) closeRelationModal(); });

relationNeo4jCopy.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(relationNeo4jQuery.textContent);
    relationNeo4jCopy.textContent = 'Copiado';
    setTimeout(() => { relationNeo4jCopy.textContent = 'Copiar'; }, 1500);
  } catch {
    // Portapapeles no disponible (ej. sin HTTPS/contexto seguro): el
    // texto ya esta visible y seleccionable a mano, no es un fallo critico.
  }
});

async function openDetail(address, { pushHistory = true } = {}) {
  const doc = docsByAddress[address];
  if (!doc) return;

  if (pushHistory && detailOverlay.hidden === false) {
    const current = document.getElementById('detail-address').textContent;
    if (current && current !== address) detailHistory.push(current);
  } else if (pushHistory) {
    detailHistory = [];
  }
  detailBack.hidden = detailHistory.length === 0;

  document.getElementById('detail-address').textContent = doc.address;
  document.getElementById('detail-status').textContent = doc.status || 'desconocido';
  document.getElementById('detail-source').textContent = (doc.discovered_via || []).join(', ') || 'no registrado';
  document.getElementById('detail-first-seen').textContent = formatDate(doc.first_seen);
  document.getElementById('detail-title').textContent = doc.http_title || 'Sin titulo HTTP disponible';
  document.getElementById('detail-title').classList.toggle('is-empty', !doc.http_title);
  document.getElementById('detail-summary-section').hidden = !doc.llm_summary;
  document.getElementById('detail-summary').textContent = doc.llm_summary || '';
  const categoryBadge = document.getElementById('detail-category-badge');
  categoryBadge.hidden = !doc.llm_category;
  categoryBadge.innerHTML = doc.llm_category
    ? `<span class="badge badge--leak">${escapeHtml(CATEGORY_LABELS[doc.llm_category] || doc.llm_category)}</span>`
    : '';
  document.getElementById('detail-services').innerHTML = renderServiceTable(doc.open_ports);
  document.getElementById('detail-tech').innerHTML = renderTechList(doc.technologies);
  document.getElementById('detail-leaks').innerHTML = renderLeaks(doc);
  document.getElementById('detail-related-tree').innerHTML = '<p class="detail-block is-empty">Consultando el grafo de infraestructura&hellip;</p>';
  document.getElementById('detail-related-list').innerHTML = '';

  detailOverlay.hidden = false;
  detailClose.focus();

  const related = await loadRelated(address);
  if (related === null) return; // el error ya se pinto en loadRelated

  relationState.address = address;
  relationState.grouped = related;
  relationState.doc = doc;
  relationState.activeType = 'all';

  refreshCompactTabs();
  refreshCompactTree(); // esto tambien refresca la lista (refreshCompactList)
}

async function ensureDocLoaded(address) {
  if (docsByAddress[address]) return;
  try {
    const res = await fetch(`/api/search?q=${encodeURIComponent(address)}`);
    const data = await res.json();
    const match = (data.results || []).find((r) => r.address === address);
    docsByAddress[address] = match || { address, status: 'desconocido' };
  } catch {
    docsByAddress[address] = { address, status: 'desconocido' };
  }
}

async function openDetailByAddress(address, opts = {}) {
  await ensureDocLoaded(address);
  await openDetail(address, opts);
}

function closeDetail() {
  detailOverlay.hidden = true;
  detailHistory = [];
}

detailClose.addEventListener('click', closeDetail);
detailBack.addEventListener('click', () => {
  const previous = detailHistory.pop();
  detailBack.hidden = detailHistory.length === 0;
  if (previous) openDetailByAddress(previous, { pushHistory: false });
});
detailOverlay.addEventListener('click', (e) => { if (e.target === detailOverlay) closeDetail(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !detailOverlay.hidden) closeDetail(); });

function switchView(view) {
  const showDashboard = view === 'dashboard';
  viewDashboard.hidden = !showDashboard;
  viewSearch.hidden = showDashboard;
  tabDashboard.classList.toggle('is-active', showDashboard);
  tabSearch.classList.toggle('is-active', !showDashboard);
  statStrip.hidden = showDashboard;
}

tabDashboard.addEventListener('click', () => switchView('dashboard'));
tabSearch.addEventListener('click', () => switchView('search'));

function renderBarList(containerId, items) {
  const container = document.getElementById(containerId);
  if (!items.length) {
    container.innerHTML = '<p class="empty-state">Sin datos disponibles.</p>';
    return;
  }
  const max = Math.max(...items.map((i) => i.count));
  container.innerHTML = items.map((item) => `
    <div class="bar-row">
      <span class="bar-row-label" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${(item.count / max) * 100}%"></span></span>
      <span class="bar-row-count">${item.count}</span>
    </div>
  `).join('');
}

function renderArtifactSummary(containerId, total, shared, topItems, idField) {
  const container = document.getElementById(containerId);
  const totalsHtml = `
    <div class="artifact-totals">
      <div><span class="stat-label">total</span><span class="stat-value">${total}</span></div>
      <div><span class="stat-label">compartidos</span><span class="stat-value" style="color:var(--amber)">${shared}</span></div>
    </div>
  `;
  if (!topItems.length) {
    container.innerHTML = totalsHtml + '<p class="empty-state">Ningun artefacto compartido por mas de un dominio todavia.</p>';
    return;
  }
  const itemsHtml = topItems.map((item) => `
    <div class="artifact-item">
      <span class="artifact-id">${escapeHtml(truncateHash(item[idField]))}</span>
      <span class="artifact-degree">${item.degree} dominios</span>
    </div>
  `).join('');
  container.innerHTML = totalsHtml + itemsHtml;
}

// ------------------------------------------------------------------
// Mapa de pistas de jurisdiccion
// ------------------------------------------------------------------

const MAP_PROJ_WIDTH = 1000;
const MAP_PROJ_HEIGHT = 500;
const MAP_VISIBILITY_KEY = 'mycelium_jurisdiction_map_visible';

// Proyeccion equirectangular simple, coherente con el viewBox del SVG
// estatico embebido en index.html (0 0 1000 500).
function projectLatLng(lat, lng) {
  const x = (lng + 180) / 360 * MAP_PROJ_WIDTH;
  const y = (90 - lat) / 180 * MAP_PROJ_HEIGHT;
  return { x, y };
}

function buildMapTooltip(point) {
  const categoryRow = point.category
    ? `<div class="map-tooltip-row"><span class="map-tooltip-label">Categoria</span><span>${escapeHtml(CATEGORY_LABELS[point.category] || point.category)}</span></div>`
    : '';
  const sourceLabel = point.source === 'tls_cert' ? 'certificado TLS' : 'titulo HTTP';
  return `
    <div class="map-tooltip-address">${escapeHtml(point.address)}</div>
    <div class="map-tooltip-row"><span class="map-tooltip-label">Pais</span><span>${escapeHtml(point.country_name)}</span></div>
    <div class="map-tooltip-row"><span class="map-tooltip-label">Titulo</span><span>${escapeHtml(point.http_title || 'sin titulo')}</span></div>
    ${categoryRow}
    <div class="map-tooltip-hint">pista via ${sourceLabel} \u00b7 clic para ver ficha</div>
  `;
}

function svgEl(tag, attrs) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, value));
  return el;
}

async function loadJurisdictionMap() {
  const statusEl = document.getElementById('jurisdiction-map-status');
  const wrapEl = document.getElementById('jurisdiction-map-wrap');
  const pointsLayer = document.getElementById('map-points-layer');
  const edgesLayer = document.getElementById('map-edges-layer');
  const tooltip = document.getElementById('jurisdiction-map-tooltip');

  try {
    const res = await fetch('/api/map');
    const data = await res.json();

    if (!data.points || !data.points.length) {
      statusEl.hidden = false;
      wrapEl.hidden = true;
      statusEl.textContent = data.search_error
        ? `No se pudo cargar: ${data.search_error}`
        : 'Sin pistas de jurisdiccion todavia (ver scripts/backfill_jurisdiction.py).';
      return;
    }

    statusEl.hidden = true;
    wrapEl.hidden = false;

    const positionByAddress = {};
    data.points.forEach((p) => { positionByAddress[p.address] = projectLatLng(p.lat, p.lng); });

    // Lineas primero, para que queden visualmente debajo de los puntos.
    edgesLayer.innerHTML = '';
    (data.edges || []).forEach((edge) => {
      const posA = positionByAddress[edge.a];
      const posB = positionByAddress[edge.b];
      if (!posA || !posB) return; // por si algun extremo no tiene pista resuelta
      edgesLayer.appendChild(svgEl('line', {
        x1: posA.x, y1: posA.y, x2: posB.x, y2: posB.y, class: 'map-edge',
      }));
    });

    pointsLayer.innerHTML = '';
    data.points.forEach((p) => {
      const pos = projectLatLng(p.lat, p.lng);
      const group = svgEl('g', {});

      group.appendChild(svgEl('circle', { cx: pos.x, cy: pos.y, r: 4, class: 'map-point-pulse' }));

      const dot = svgEl('circle', { cx: pos.x, cy: pos.y, r: 4, class: 'map-point' });
      dot.addEventListener('mouseenter', () => {
        tooltip.innerHTML = buildMapTooltip(p);
        tooltip.hidden = false;
      });
      dot.addEventListener('mousemove', (e) => {
        const wrapRect = wrapEl.getBoundingClientRect();
        tooltip.style.left = `${e.clientX - wrapRect.left + 14}px`;
        tooltip.style.top = `${e.clientY - wrapRect.top + 14}px`;
      });
      dot.addEventListener('mouseleave', () => { tooltip.hidden = true; });
      dot.addEventListener('click', () => openDetailByAddress(p.address));
      group.appendChild(dot);

      pointsLayer.appendChild(group);
    });
  } catch (err) {
    statusEl.hidden = false;
    wrapEl.hidden = true;
    statusEl.textContent = `No se pudo cargar el mapa: ${err.message}`;
  }
}

function applyMapVisibility(visible) {
  const body = document.getElementById('jurisdiction-map-body');
  const btn = document.getElementById('map-toggle-btn');
  body.hidden = !visible;
  btn.textContent = visible ? 'Ocultar mapa' : 'Mostrar mapa';
  btn.setAttribute('aria-pressed', String(visible));
}

function initMapToggle() {
  const btn = document.getElementById('map-toggle-btn');
  const stored = localStorage.getItem(MAP_VISIBILITY_KEY);
  // Por defecto visible la primera vez (sin preferencia guardada aun).
  applyMapVisibility(stored === null ? true : stored === 'true');

  btn.addEventListener('click', () => {
    const willBeVisible = document.getElementById('jurisdiction-map-body').hidden;
    applyMapVisibility(willBeVisible);
    localStorage.setItem(MAP_VISIBILITY_KEY, String(willBeVisible));
  });
}

async function loadDashboard() {
  try {
    const res = await fetch('/api/dashboard');
    const data = await res.json();

    if (data.stats) {
      document.getElementById('dash-total').textContent = data.stats.total ?? '0';
      document.getElementById('dash-alive').textContent = data.stats.by_status?.alive ?? '0';
      document.getElementById('dash-leaks').textContent = data.stats.with_leaks ?? '0';
      document.getElementById('dash-relations').textContent = data.stats.with_relations ?? '0';
    } else {
      ['dash-total', 'dash-alive', 'dash-leaks', 'dash-relations'].forEach((id) => {
        document.getElementById(id).textContent = 'N/D';
      });
    }

    if (data.technologies) {
      renderBarList('dashboard-technologies', data.technologies);
    } else {
      document.getElementById('dashboard-technologies').innerHTML =
        `<p class="error-state">No se pudo cargar: ${escapeHtml(data.search_error || 'error desconocido')}</p>`;
    }

    if (data.ports) {
      renderBarList('dashboard-ports', data.ports);
    } else {
      document.getElementById('dashboard-ports').innerHTML =
        `<p class="error-state">No se pudo cargar: ${escapeHtml(data.search_error || 'error desconocido')}</p>`;
    }

    if (data.categories && data.categories.length) {
      renderBarList('dashboard-categories', data.categories);
    } else if (data.categories) {
      document.getElementById('dashboard-categories').innerHTML =
        '<p class="empty-state">Sin categorias asignadas todavia (ver scripts/backfill_categories.py).</p>';
    } else {
      document.getElementById('dashboard-categories').innerHTML =
        `<p class="error-state">No se pudo cargar: ${escapeHtml(data.search_error || 'error desconocido')}</p>`;
    }

    if (data.artifacts) {
      renderArtifactSummary(
        'dashboard-certificates',
        data.artifacts.certificates_total, data.artifacts.certificates_shared,
        data.artifacts.top_certificates, 'sha256',
      );
      renderArtifactSummary(
        'dashboard-jarm',
        data.artifacts.jarm_total, data.artifacts.jarm_shared,
        data.artifacts.top_jarm, 'hash',
      );
      renderArtifactSummary(
        'dashboard-ssh-keys',
        data.artifacts.ssh_keys_total, data.artifacts.ssh_keys_shared,
        data.artifacts.top_ssh_keys, 'fingerprint',
      );
      renderArtifactSummary(
        'dashboard-pgp',
        data.artifacts.pgp_keys_total, data.artifacts.pgp_keys_shared,
        data.artifacts.top_pgp_keys, 'hash',
      );
      renderArtifactSummary(
        'dashboard-crypto',
        data.artifacts.crypto_addresses_total, data.artifacts.crypto_addresses_shared,
        data.artifacts.top_crypto_addresses, 'id',
      );
    } else {
      const msg = `<p class="error-state">No se pudo consultar Neo4j: ${escapeHtml(data.graph_error || 'error desconocido')}</p>`;
      document.getElementById('dashboard-certificates').innerHTML = msg;
      document.getElementById('dashboard-jarm').innerHTML = msg;
      document.getElementById('dashboard-ssh-keys').innerHTML = msg;
      document.getElementById('dashboard-pgp').innerHTML = msg;
      document.getElementById('dashboard-crypto').innerHTML = msg;
    }
  } catch (err) {
    const msg = `<p class="error-state">No se pudo cargar el resumen: ${escapeHtml(err.message)}</p>`;
    document.getElementById('dashboard-technologies').innerHTML = msg;
    document.getElementById('dashboard-ports').innerHTML = msg;
    document.getElementById('dashboard-certificates').innerHTML = msg;
    document.getElementById('dashboard-jarm').innerHTML = msg;
    document.getElementById('dashboard-ssh-keys').innerHTML = msg;
    document.getElementById('dashboard-pgp').innerHTML = msg;
    document.getElementById('dashboard-crypto').innerHTML = msg;
    ['dash-total', 'dash-alive', 'dash-leaks', 'dash-relations'].forEach((id) => {
      document.getElementById(id).textContent = 'N/D';
    });
  }
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  runSearch();
});

onlyLeaksInput.addEventListener('change', runSearch);
prevPageBtn.addEventListener('click', () => loadList(currentPage - 1));
nextPageBtn.addEventListener('click', () => loadList(currentPage + 1));

Object.entries(statButtons).forEach(([key, btn]) => {
  btn.addEventListener('click', () => {
    switchView('search');
    qInput.value = '';
    onlyLeaksInput.checked = key === 'leaks';
    loadList(1, key);
  });
});

loadStats();
loadList(1, 'all');
loadDashboard();
initMapToggle();
loadJurisdictionMap();
switchView('dashboard');
