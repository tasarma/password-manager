import { invoke } from "@tauri-apps/api/core";
import { showToast } from "./toastManager";
import { initPasswordManager } from "./passwordManager";
import { deleteDatabaseFolder, isDbExist } from "./api";

// State to track authentication
let isAuthenticated = false;

// Check if user is already authenticated
export async function checkAuthStatus(): Promise<boolean> {
  const authStatus = sessionStorage.getItem('vaultpass_authenticated');
  isAuthenticated = authStatus === 'true';
  return isAuthenticated;
}


// Handle registration
export async function register(masterPassword: string, encryptDb: boolean): Promise<void> {
  try {
    await invoke('register', { masterPassword, encryptDb });
    sessionStorage.setItem('vaultpass_authenticated', 'true');
    isAuthenticated = true;
    showToast('Registration successful!', 'success');
    toggleAuthView(true);
  } catch (error) {
    console.error('Registration failed:', error);
    showToast('Registration failed. Please try again.', 'error');
  }
}

// Handle login
export async function login(masterPassword: string): Promise<void> {
  try {
    await invoke('login', { masterPassword});
    sessionStorage.setItem('vaultpass_authenticated', 'true');
    isAuthenticated = true;
    showToast('Login successful!', 'success');
    toggleAuthView(true);
    await initPasswordManager();
    window.location.reload();
  } catch (error) {
    console.error('Login failed:', error);
    showToast(`${error}`, 'error');
  }
}

// Handle logout
export function logout(): void {
  sessionStorage.removeItem('vaultpass_authenticated');
  isAuthenticated = false;
  toggleAuthView(false);
  showToast('Logged out successfully', 'success');
}

// Toggle between auth view and main app view
export function toggleAuthView(isLoggedIn: boolean): void {
  const authContainer = document.getElementById('authContainer');
  const mainContainer = document.getElementById('mainContainer');
  
  if (authContainer && mainContainer) {
    if (isLoggedIn) {
      authContainer.style.display = 'none';
      mainContainer.style.display = 'block';
    } else {
      authContainer.style.display = 'block';
      mainContainer.style.display = 'none';
    }
  }
}

// Initialize auth UI components
export function initAuth(): void {
  // Switch between login and register tabs
  const loginTab = document.getElementById('loginTab');
  const registerTab = document.getElementById('registerTab');
  const loginForm = document.getElementById('loginForm');
  const registerForm = document.getElementById('registerForm');
  
  // Add password visibility toggle functionality
  const loginPasswordInput = document.getElementById('loginPassword') as HTMLInputElement;
  const registerPasswordInput = document.getElementById('registerPassword') as HTMLInputElement;
  const confirmPasswordInput = document.getElementById('confirmPassword') as HTMLInputElement;
  
  const loginToggleBtn = document.getElementById('loginTogglePassword');
  const registerToggleBtn = document.getElementById('registerTogglePassword');
  const confirmToggleBtn = document.getElementById('confirmTogglePassword');

  function togglePasswordVisibility(input: HTMLInputElement, toggleBtn: HTMLElement | null): void {
    if (!toggleBtn) return;
    const icon = toggleBtn.querySelector('i');
    if (!icon) return;
    
    if (input.type === 'password') {
      input.type = 'text';
      icon.className = 'fas fa-eye-slash';
    } else {
      input.type = 'password';
      icon.className = 'fas fa-eye';
    }
  }

  loginToggleBtn?.addEventListener('click', () => {
    if (loginPasswordInput) {
      togglePasswordVisibility(loginPasswordInput, loginToggleBtn);
    }
  });

  registerToggleBtn?.addEventListener('click', () => {
    if (registerPasswordInput) {
      togglePasswordVisibility(registerPasswordInput, registerToggleBtn);
    }
  });

  confirmToggleBtn?.addEventListener('click', () => {
    if (confirmPasswordInput) {
      togglePasswordVisibility(confirmPasswordInput, confirmToggleBtn);
    }
  });
  
  loginTab?.addEventListener('click', () => {
    loginTab.classList.add('active');
    registerTab?.classList.remove('active');
    if (loginForm) loginForm.style.display = 'block';
    if (registerForm) registerForm.style.display = 'none';
  });
  
  registerTab?.addEventListener('click', () => {
    registerTab.classList.add('active');
    loginTab?.classList.remove('active');
    if (registerForm) registerForm.style.display = 'block';
    if (loginForm) loginForm.style.display = 'none';
  });
  
  // Handle login form submission
  loginForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const passwordInput = document.getElementById('loginPassword') as HTMLInputElement;
    if (passwordInput && passwordInput.value) {
      await login(passwordInput.value);
    }
  });
  
  // Handle register form submission
  registerForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const isDbAlreadyExist = await isDbExist();
    if (isDbAlreadyExist) {
    const confirmDelete = confirm(
      "A database already exists.\n\nIf you proceed, all existing data will be permanently deleted and cannot be recovered.\n\nDo you want to continue?"
    );

    if (!confirmDelete) {
      showToast('Registration cancelled.', 'info');
      return;
    }

    await deleteDatabaseFolder();
    showToast('Database deleted successfully', 'success');
  }

    const encryptChoice = document.getElementById("encryptDb") as HTMLSelectElement;
    const encryptDb = encryptChoice?.value === 'yes' ? true : false;
    const passwordInput = document.getElementById('registerPassword') as HTMLInputElement;
    const confirmInput = document.getElementById('confirmPassword') as HTMLInputElement;
    
    if (passwordInput && confirmInput) {
      if (passwordInput.value !== confirmInput.value) {
        showToast('Passwords do not match', 'error');
        return;
      }
      
      if (passwordInput.value.length <= 0) {
        showToast('Password must be at least 1 characters', 'error');
        return;
      }
      
      await register(passwordInput.value, encryptDb);
    }
  });


  
  // Handle logout
  const logoutItem = document.getElementById('logoutItem');
  logoutItem?.addEventListener('click', (e) => {
    e.preventDefault();
    logout();
  });
  
  // Check if user is already authenticated
  checkAuthStatus().then(async isAuth => {
    toggleAuthView(isAuth);
    if (isAuth) {
      await initPasswordManager();
    }
  });
}