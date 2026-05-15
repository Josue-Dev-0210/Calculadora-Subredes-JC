function ipAEntero(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0) >>> 0;
}

function enteroAIp(n) {
  return [24, 16, 8, 0].map(s => (n >> s) & 0xff).join('.');
}

function cidrAMascara(cidr) {
  return cidr === 0 ? 0 : (0xffffffff << (32 - cidr)) >>> 0;
}

function aBinario(ip) {
  return ip.split('.').map(o => parseInt(o).toString(2).padStart(8, '0')).join('.');
}

function formatearCantidad(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K';
  return n.toString();
}

function obtenerClase(ip) {
  const primero = parseInt(ip.split('.')[0]);
  if (primero < 128) return 'A';
  if (primero < 192) return 'B';
  if (primero < 224) return 'C';
  if (primero < 240) return 'D';
  return 'E';
}

function obtenerTipo(ip) {
  const [a, b] = ip.split('.').map(Number);
  if (a === 10)                        return 'Privada (RFC1918)';
  if (a === 172 && b >= 16 && b <= 31) return 'Privada (RFC1918)';
  if (a === 192 && b === 168)          return 'Privada (RFC1918)';
  if (a === 127)                       return 'Loopback';
  if (a === 169 && b === 254)          return 'Link-local (APIPA)';
  if (a >= 224 && a <= 239)            return 'Multicast';
  return 'Pública';
}

function validar(ip, cidr) {
  const octetos = ip.split('.');
  if (octetos.length !== 4) return 'La IP debe tener 4 octetos.';
  for (const o of octetos) {
    const n = parseInt(o);
    if (isNaN(n) || n < 0 || n > 255) return `Octeto inválido: "${o}". Rango 0-255.`;
  }
  const c = parseInt(cidr);
  if (isNaN(c) || c < 0 || c > 32) return 'El prefijo CIDR debe estar entre 0 y 32.';
  return null;
}


function calcular(ip, cidr) {
  const mascara    = cidrAMascara(cidr);
  const ipEntero   = ipAEntero(ip);
  const red        = (ipEntero & mascara) >>> 0;
  const difusion   = (red | ~mascara) >>> 0;
  const comodin    = (~mascara) >>> 0;
  const primerHost = cidr < 31 ? red + 1 : red;
  const ultimoHost = cidr < 31 ? difusion - 1 : difusion;
  const cantHosts  = cidr >= 31
    ? Math.pow(2, 32 - cidr)
    : Math.pow(2, 32 - cidr) - 2;

  return {
    red:        enteroAIp(red),
    mascara:    enteroAIp(mascara),
    comodin:    enteroAIp(comodin),
    difusion:   enteroAIp(difusion),
    primerHost: enteroAIp(primerHost),
    ultimoHost: enteroAIp(ultimoHost),
    cantHosts:  Math.max(0, cantHosts),
    cidr,
    clase:      obtenerClase(ip),
    tipo:       obtenerTipo(ip),
  };
}


function renderizar(r) {
  document.getElementById('resultados-de-red').textContent     = r.red + '/' + r.cidr;
  document.getElementById('red-binaria').textContent           = aBinario(r.red);
  document.getElementById('resultados-de-mascara').textContent = r.mascara;
  document.getElementById('mascara-binaria').textContent       = aBinario(r.mascara);
  document.getElementById('resultados-de-comodin').textContent = r.comodin;
  document.getElementById('comodin-binaria').textContent       = aBinario(r.comodin);
  document.getElementById('resultados-de-difusion').textContent = r.difusion;
  document.getElementById('difusion-binaria').textContent      = aBinario(r.difusion);
  document.getElementById('resultados-de-rango').textContent   = r.primerHost + ' — ' + r.ultimoHost;
  document.getElementById('rango-subred').textContent          = formatearCantidad(r.cantHosts) + ' hosts disponibles';
  document.getElementById('resultados-de-clase').textContent   = 'Clase ' + r.clase;
  document.getElementById('tipo-subred').textContent           = r.tipo;

  renderizarBits(r.cidr);
  renderizarBarra(r);

  document.getElementById('resultados').classList.remove('hidden');
}

function renderizarBits(cidr) {
  const wrap = document.getElementById('binario-visual');
  wrap.innerHTML = '';

  for (let octeto = 0; octeto < 4; octeto++) {
    const grupo = document.createElement('div');
    grupo.className = 'bit-group';

    for (let bit = 0; bit < 8; bit++) {
      const pos = octeto * 8 + bit;
      const el  = document.createElement('div');
      el.className   = 'bit ' + (pos < cidr ? 'net' : 'host');
      el.textContent = pos < cidr ? '1' : '0';
      grupo.appendChild(el);
    }

    wrap.appendChild(grupo);

    if (octeto < 3) {
      const sep = document.createElement('div');
      sep.style.cssText = 'width:6px;display:flex;align-items:center;justify-content:center;color:#444;font-size:10px;';
      sep.textContent = '·';
      wrap.appendChild(sep);
    }
  }
}

function renderizarBarra(r) {
  document.getElementById('etiqueta-red').textContent          = r.red;
  document.getElementById('etiqueta-primer-host').textContent  = r.primerHost;
  document.getElementById('etiqueta-ultimo-host').textContent  = r.ultimoHost;
  document.getElementById('etiqueta-difusion').textContent     = r.difusion;
}


const ipEntrada   = document.getElementById('ip-entrada');
const cidrEntrada = document.getElementById('cidr-entrada');
const btnCalcular = document.getElementById('btn-calcular');
const mensajeError = document.getElementById('mensaje-error');

function mostrarError(msg) {
  mensajeError.textContent = msg;
  mensajeError.classList.remove('hidden');
}

function limpiarError() {
  mensajeError.classList.add('hidden');
}

function ejecutar() {
  const ip   = ipEntrada.value.trim();
  const cidr = cidrEntrada.value.trim();

  const error = validar(ip, cidr);
  if (error) { mostrarError(error); return; }

  limpiarError();
  const resultado = calcular(ip, parseInt(cidr));
  renderizar(resultado);
}

btnCalcular.addEventListener('click', ejecutar);
ipEntrada.addEventListener('keydown',   e => { if (e.key === 'Enter') ejecutar(); });
cidrEntrada.addEventListener('keydown', e => { if (e.key === 'Enter') ejecutar(); });

document.querySelectorAll('.btn-rapido').forEach(btn => {
  btn.addEventListener('click', () => {
    ipEntrada.value   = btn.dataset.ip;
    cidrEntrada.value = btn.dataset.cidr;
    ejecutar();
  });
});


ipEntrada.value   = '192.168.1.0';
cidrEntrada.value = '24';

function ejecutar() {
  const ip   = ipEntrada.value.trim();
  const cidr = cidrEntrada.value.trim();

  const error = validar(ip, cidr);
  if (error) { mostrarError(error); return; }

  limpiarError();
  const resultado = calcular(ip, parseInt(cidr));
  renderizar(resultado);

  
  const cant = document.getElementById('num-subredes').value;
  if (cant) dividirSubredes();
}

document.getElementById('btn-subredes').addEventListener('click', dividirSubredes);

function dividirSubredes() {
  const ip   = ipEntrada.value.trim();
  const cidr = parseInt(cidrEntrada.value.trim());
  const cant = parseInt(document.getElementById('num-subredes').value);

  const errBase = validar(ip, cidrEntrada.value.trim());
  if (errBase) { mostrarError(errBase); return; }

  if (isNaN(cant) || cant < 1) {
    mostrarError('Ingresa cuántas subredes necesitas (mínimo 1).');
    return;
  }

  const bitsNecesarios = Math.ceil(Math.log2(cant));
  const nuevoCidr      = cidr + bitsNecesarios;

  if (nuevoCidr > 30) {
    mostrarError(`No es posible crear ${cant} subredes desde /${cidr}. El CIDR resultante /${nuevoCidr} no deja hosts utilizables.`);
    return;
  }

  const mascara  = cidrAMascara(nuevoCidr);
  const tamano   = Math.pow(2, 32 - nuevoCidr);
  const redBase  = (ipAEntero(ip) & cidrAMascara(cidr)) >>> 0;

  const subredes = [];
  for (let i = 0; i < cant; i++) {
    const redInt     = (redBase + i * tamano) >>> 0;
    const difInt     = (redInt + tamano - 1) >>> 0;
    subredes.push({
      indice:     i + 1,
      red:        enteroAIp(redInt),
      mascara:    enteroAIp(mascara),
      primerHost: enteroAIp(redInt + 1),
      ultimoHost: enteroAIp(difInt - 1),
      difusion:   enteroAIp(difInt),
      hostsUtil:  tamano - 2,
      cidr:       nuevoCidr,
    });
  }

  renderizarTablaSubredes(subredes, cant, nuevoCidr);
  limpiarError();
}

function renderizarTablaSubredes(subredes, solicitadas, cidr) {
  const anterior = document.getElementById('tabla-subredes-wrap');
  if (anterior) anterior.remove();

  const wrap = document.createElement('div');
  wrap.id = 'tabla-subredes-wrap';

  wrap.innerHTML = `
    <div id="tabla-subredes-header">
      <h3>subredes generadas</h3>
      <span id="tabla-subredes-meta">
        solicitadas: <b>${solicitadas}</b> &nbsp;·&nbsp;
        bloque: <b>/${cidr}</b> &nbsp;·&nbsp;
        hosts/subred: <b>${subredes[0].hostsUtil}</b>
      </span>
    </div>
    <div id="tabla-subredes-scroll">
      <table id="tabla-subredes">
        <thead>
          <tr>
            <th>#</th>
            <th>Red</th>
            <th>Máscara</th>
            <th>Primer Host</th>
            <th>Último Host</th>
            <th>Difusión</th>
            <th>Hosts</th>
          </tr>
        </thead>
        <tbody id="tabla-subredes-body"></tbody>
      </table>
    </div>
  `;

  document.getElementById('app').appendChild(wrap);

  const tbody = document.getElementById('tabla-subredes-body');
  subredes.forEach(s => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="td-indice">${s.indice}</td>
      <td class="td-red">${s.red}/${s.cidr}</td>
      <td class="td-mask">${s.mascara}</td>
      <td class="td-host">${s.primerHost}</td>
      <td class="td-host">${s.ultimoHost}</td>
      <td class="td-bcast">${s.difusion}</td>
      <td class="td-count">${s.hostsUtil}</td>
    `;
    tbody.appendChild(tr);
  });
}
document.getElementById('num-subredes').addEventListener('keydown', e => {
  if (e.key === 'Enter') ejecutar();
});