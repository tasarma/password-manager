import { getPassword, addPassword, updatePassword } from "./api";
import { PasswordType } from "./types.ts";
import { showToast } from "./toastManager";
import { isValidUrl } from "./utils";

// DOM Elements
const passwordModal = document.getElementById('passwordModal') as HTMLElement;
const closeModal = document.getElementById('closeModal') as HTMLElement;
const cancelPassword = document.getElementById('cancelPassword') as HTMLElement;
const togglePassword = document.getElementById('togglePassword') as HTMLElement;
const formPassword = document.getElementById('formPassword') as HTMLInputElement;

// Current editable password ID
let currentPasswordId: string | null = null;

// Open password modal
export async function openPasswordModal(passwordId: string | null = null): Promise<void> {
  currentPasswordId =  passwordId;

  const titleInput = document.getElementById('formTitle') as HTMLInputElement;
  const usernameInput = document.getElementById('formUsername') as HTMLInputElement;
  const urlInput = document.getElementById('formUrl') as HTMLInputElement;
  const passwordInput = document.getElementById('formPassword') as HTMLInputElement;
  const notesInput = document.getElementById('formNotes') as HTMLInputElement;
  const modalTitle = document.querySelector('.modal-title')!;
  const saveButton = document.getElementById('savePassword')!;

  if (passwordId) {
    // Editing existing password
    try {
      const password: PasswordType | null = await getPassword(passwordId);

      if (password) {
        titleInput.value = password.title;
        usernameInput.value = password.username;
        urlInput.value = password.url || '';
        passwordInput.value = password.password;
        notesInput.value = password.notes || '';

        modalTitle.textContent = 'Edit Password';
        saveButton.textContent = 'Update Password';
      } else {
        showToast(`Password with ID ${passwordId} not found.`, 'danger');
      }
    } catch (error) {
      console.error('Failed to fetch password for editing:', error);
    }
  } else {
    // Adding new password
    titleInput.value = '';
    usernameInput.value = '';
    urlInput.value = '';
    passwordInput.value = '';
    notesInput.value = '';

    modalTitle.textContent = 'Add New Password';
    saveButton.textContent = 'Save Password';
  }

  passwordModal.classList.add('active');
}

// Close password modal
function closePasswordModal(): void {
    passwordModal.classList.remove('active');
    currentPasswordId = null;
}

// Toggle password visibility
function togglePasswordVisibility(): void {
  const icon = togglePassword.querySelector('i')!;
  if (formPassword.type === 'password') {
    formPassword.type = 'text';
    icon.className = 'fas fa-eye-slash';
  } else {
    formPassword.type = 'password';
    icon.className = 'fas fa-eye';
  }
}

async function handlePasswordSubmit(event: Event) {
  event.preventDefault();

  const title = (document.getElementById('formTitle') as HTMLInputElement).value.trim();
  const username = (document.getElementById('formUsername') as HTMLInputElement).value.trim();
  const password = (document.getElementById('formPassword') as HTMLInputElement).value.trim();
  const url = (document.getElementById('formUrl') as HTMLInputElement).value.trim() || undefined;
  const notes = (document.getElementById('formNotes') as HTMLInputElement).value.trim() || undefined;

  const errors: string[] = [];

  if (!title) errors.push("Title is required");
  if (!username) errors.push("Username is required");
  if (url && !isValidUrl(url)) errors.push("Invalid URL format");
  if (notes && notes.length > 500) errors.push("Notes cannot exceed 500 characters");

  if (errors.length > 0) {
    errors.forEach(err => showToast(err, "warning"));
    return;
  }

  try {
    if (currentPasswordId) {
        await updatePassword({
          id: currentPasswordId,
          title,
          username,
          password,
          url,
          notes,
        });
        showToast("Password updated successfully!", "success");
      } else {
        await addPassword({ title, username, password, url, notes });
        showToast("Password added successfully!", "success");
      }

    setTimeout(() => {
      closePasswordModal();
      window.location.reload();
    }, 700);
  } catch (error) {
    console.error('Failed to save password:', error);
    showToast("Failed to save password. Please try again.", "danger");
  }
}

// Set up modal event listeners
export function setupModalListeners(): void {
    const addPasswordBtn = document.getElementById('addPasswordBtn') as HTMLElement;
    const passwordForm = document.getElementById('passwordForm') as HTMLFormElement;

    addPasswordBtn.addEventListener('click', () => openPasswordModal(null));
    closeModal.addEventListener('click', () => closePasswordModal());
    cancelPassword.addEventListener('click', () => closePasswordModal());
    togglePassword.addEventListener('click', togglePasswordVisibility);

    passwordForm.addEventListener('submit', handlePasswordSubmit);
}
