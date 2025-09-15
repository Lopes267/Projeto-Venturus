document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('registerForm');
  const tipoSelect = document.getElementById('tipo');
  const especialidadeWrapper = document.getElementById('especialidadeWrapper');
  const especialidadeInput = document.getElementById('especialidade');
  const statusEl = document.getElementById('registerStatus');

  function toggleEspecialidade() {
    if (!tipoSelect) return;
    if (tipoSelect.value === 'medico') {
      especialidadeWrapper.style.display = 'block';
    } else {
      especialidadeWrapper.style.display = 'none';
     if (especialidadeInput) especialidadeInput.value = '';
    }
  }

  if (tipoSelect) tipoSelect.addEventListener('change', toggleEspecialidade);
  toggleEspecialidade();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    statusEl.textContent = '';
  const nome = document.getElementById('name').value.trim();
  const email = (document.getElementById('email') && document.getElementById('email').value.trim().toLowerCase()) || '';
  const tipo = (document.getElementById('tipo') && document.getElementById('tipo').value) || 'cliente';
  const especialidade = (document.getElementById('especialidade') && document.getElementById('especialidade').value.trim()) || '';
  const senha = document.getElementById('password').value;

    if (!nome || !senha || !email) {
      statusEl.style.color = 'red';
      statusEl.textContent = 'Preencha todos os campos obrigatórios.';
      return;
    }

  const payload = { nome, email, tipo, especialidade, senha };

    try {
      const res = await fetch('http://localhost:5000/registrar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (res.status === 201) {
        statusEl.style.color = 'green';
        statusEl.textContent = 'Cadastro realizado com sucesso! Redirecionando para login...';
        setTimeout(() => { window.location.href = 'login.html'; }, 1200);
      } else {
        statusEl.style.color = 'red';
        statusEl.textContent = data.erro || data.message || 'Erro ao cadastrar';
      }
    } catch (err) {
      statusEl.style.color = 'red';
      statusEl.textContent = 'Erro de conexão com servidor';
      console.error(err);
    }
  });
});