
function getQueryParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name) || '';
}

window.onload = function() {
  const nome = getQueryParam('nome');
  if (nome) {
    document.getElementById('info').innerText = `Bem-vindo, ${decodeURIComponent(nome)}!`;
  } else {
    document.getElementById('info').innerText = 'Você está logado!';
  }
};
