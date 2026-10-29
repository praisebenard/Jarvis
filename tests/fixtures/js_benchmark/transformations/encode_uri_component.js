const input = location.search;
const encoded = encodeURIComponent(input);
target.innerHTML = encoded;
