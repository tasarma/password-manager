import { getPasswords, deletePassword } from "./api";
import { openPasswordModal } from "./modalManager";
import { PasswordType } from "./types";

const passwordList = document.getElementById('passwordList') as HTMLElement;
const searchInput = document.getElementById('searchInput') as HTMLInputElement;

let allPasswords: PasswordType[] = [];
let filteredPasswords: PasswordType[] = [];
let renderIndex = 0;
const batchSize = 4;

searchInput.addEventListener('input', () => {
  const query = searchInput.value.trim().toLowerCase();
  filteredPasswords = allPasswords.filter(p =>
    p.title.toLowerCase().includes(query) ||
    p.username.toLowerCase().includes(query) ||
    (p.url?.toLowerCase().includes(query) ?? false)
  );

  renderIndex = 0;
  passwordList.innerHTML = '';
  renderNextBatch();
});

function renderNextBatch() {
  const nextItems = filteredPasswords.slice(renderIndex, renderIndex + batchSize);

  nextItems.forEach((password) => {
    const passwordCard = document.createElement('div');
    passwordCard.className = 'password-card';
    passwordCard.innerHTML = `
      <div class="password-header">
        <div>
          <h3 class="password-title">${password.title}</h3>
          <p class="password-username">${password.username}</p>
        </div>
        <div class="password-actions">
          <button class="edit-password" data-id="${password.id}">
            <i class="fas fa-edit"></i>
          </button>
          <button class="delete-password" data-id="${password.id}">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </div>
      <div class="password-meta">
        <span>
          <i class="fas fa-calendar-alt"></i>
          ${password.created_at? new Date(password.created_at).toLocaleDateString('en-US', {
              year: 'numeric',
              month: 'long',
              day: 'numeric'
          }) : 'N/A'}

        </span>
        ${password.url ? `
        <span>
          <i class="fas fa-link"></i>
          <a href="${password.url}" target="_blank">Website</a>
        </span>` : ''}
      </div>
    `;
    passwordList.appendChild(passwordCard);
  });

  renderIndex += nextItems.length;
}

passwordList.addEventListener('click', async (event: Event) => {
  const target = event.target as HTMLElement;

  if (target.closest('.edit-password')) {
    const id = (target.closest('.edit-password') as HTMLElement).dataset.id;
    if (id) openPasswordModal(id);
  }

  if (target.closest('.delete-password')) {
    const id = (target.closest('.delete-password') as HTMLElement).dataset.id;
    if (id) {
      await deletePassword(id);
      await initPasswordManager(); 
    }
  }
});

export async function initPasswordManager(): Promise<void> {
  allPasswords = await getPasswords();
  filteredPasswords = [...allPasswords];
  renderIndex = 0;

  passwordList.innerHTML = '';

  if (filteredPasswords.length === 0) {
    const emptyState = document.createElement('div');
    passwordList.className = 'empty-state';
    emptyState.innerHTML = `
      <i class="fas fa-key"></i>
      <h3>No Passwords Saved</h3>
      <p>You haven't saved any passwords yet. Click the button above to add your first password.</p>
    `;
    passwordList.appendChild(emptyState);
  } else {
    renderNextBatch();
  }
}
