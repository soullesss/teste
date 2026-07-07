const button = document.querySelector("#pingButton");
const status = document.querySelector("#status");

button?.addEventListener("click", () => {
  const now = new Date().toLocaleTimeString("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  status.textContent = `Funcionou. Clique recebido as ${now}.`;
});
