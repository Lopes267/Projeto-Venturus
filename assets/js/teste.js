document.getElementById('formPessoa').onsubmit = async function(e) {
  e.preventDefault();
  const form = e.target;
  const pessoa = {
    nome: form.nome.value,
    email: form.email.value.trim().toLowerCase(),
    tipo: form.tipo.value,
    especialidade: form.tipo.value === 'medico' ? form.especialidade.value : null,
    senha: form.senha.value
  };
  const res = await fetch('http://localhost:5000/registrar', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(pessoa)
  });
  if (res.ok) {
    window.location.href = 'login.html';
  } else {
    listarPessoas();
  }
};

async function listarPessoas() {
  const res = await fetch('http://localhost:5000/pessoas');
  const pessoas = await res.json();
  const lista = document.getElementById('listaPessoas');
  lista.innerHTML = pessoas.map(p => `<li>${p.nome} (${p.tipo}${p.tipo === 'medico' ? ' - ' + p.especialidade : ''})</li>`).join('');
}

listarPessoas();

// Preselect tipo if provided in query string
function getQueryParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name) || '';
}
const tipoParam = getQueryParam('tipo');
if (tipoParam) {
  const tipoSelect = document.querySelector('select[name="tipo"]');
  if (tipoSelect) {
    tipoSelect.value = tipoParam;
  }
}