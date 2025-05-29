import { initPasswordManager } from './passwordManager';
import { setupModalListeners } from './modalManager';
import { initAuth } from './auth';

// Initialize the app
window.addEventListener('DOMContentLoaded', () => {
    initAuth();
    initPasswordManager();
    setupModalListeners();
});
