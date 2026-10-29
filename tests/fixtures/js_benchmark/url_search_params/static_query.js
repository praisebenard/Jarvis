const params = new URLSearchParams("?message=static");
const message = params.get("message");
target.innerHTML = message;
