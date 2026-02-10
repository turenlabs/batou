// DOM-based XSS: user-controlled data flows into innerHTML

function loadSearchResults() {
  const params = new URLSearchParams(window.location.search);
  const query = params.get('q');

  // VULNERABLE: user input from URL params assigned to innerHTML
  document.getElementById('search-term').innerHTML = query;

  // VULNERABLE: document.write with user-controlled URL parameter
  document.write('<h2>Results for: ' + query + '</h2>');
}

function displayUserProfile(userData) {
  const container = document.getElementById('profile');
  // VULNERABLE: innerHTML assignment with dynamic content from user input
  container.innerHTML = '<div class="name">' + userData.name + '</div>';

  // VULNERABLE: setAttribute with dangerous attribute
  const link = document.createElement('a');
  link.setAttribute('href', userData.url);
  container.appendChild(link);
}

window.addEventListener('DOMContentLoaded', loadSearchResults);
