// Source: OWASP Juice Shop - DOM XSS via search query reflection
// Expected: BATOU-GEN-018 (innerHTML assignment), BATOU-XSS-001 (innerHTML)
// OWASP: A03:2021 - Injection (DOM-based XSS)

export function initSearchPage(): void {
  const params = new URLSearchParams(window.location.search);
  const query = params.get('q') || '';

  const searchBox = document.getElementById('search-input') as HTMLInputElement;
  searchBox.value = query;

  const resultsDiv = document.getElementById('search-results');
  if (resultsDiv) {
    resultsDiv.innerHTML = `<h2>Search results for: ${query}</h2>`;
  }

  document.title = `Search: ${query} - Shop`;
}

export function renderUserProfile(profileData: string): void {
  const container = document.getElementById('profile');
  if (container) {
    container.innerHTML = profileData;
  }
}
