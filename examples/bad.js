// Intentionally bad JavaScript: a demo target for codelens.
var apiUrl = "https://example.com";

function render(userHtml, id) {
  document.getElementById("out").innerHTML = userHtml;
  if (id == 5) {
    console.log("rendering", id);
  }
  try {
    return eval("(" + userHtml + ")");
  } catch (e) {}
}
