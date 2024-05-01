
const rows = document.querySelectorAll('tr'); // Seleziona tutte le righe della tabella

for (const row of rows) {
  const referenceContainer = row.querySelector('#reference-container'); // Seleziona il contenitore reference nella riga corrente
  const links = referenceContainer.querySelectorAll('a');

  const maxLinksToShow = 3; // Numero massimo di link da visualizzare

  for (let i = maxLinksToShow; i < links.length; i++) {
    links[i].style.display = 'none';
  }
}
