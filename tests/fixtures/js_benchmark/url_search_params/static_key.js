const params = new URLSearchParams(location.search);
const message = params.get("message");
document.getElementById("output").innerHTML = message;
