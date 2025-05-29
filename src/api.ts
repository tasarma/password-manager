import { invoke } from "@tauri-apps/api/core";

import { PasswordType } from './types';
import { showToast } from './toastManager';


// Fetch all passwords
export async function getPasswords(): Promise<PasswordType[]> {
  try {
    const passwords: PasswordType[] = await invoke('get_passwords');
    return passwords;
    
  } catch (error) {
    console.error('Failed to fetch passwords', error);
    return [];
  }
}

export async function getPassword(passwordId: string): Promise<PasswordType | null> {
  try {
    const password: PasswordType | undefined = await invoke('get_password_by_id', { id: passwordId });
    return password ?? null;
    
  } catch (error) {
    console.error('Failed to fetch passwords', error);
    return null;
  }
}

// Add a password
export async function addPassword(params: Omit<PasswordType, 'id' | 'createdAt' | 'updatedAt'>) {
  try {
    const result: string = await invoke('add_password', {
      title: params.title,
      username: params.username,
      password: params.password,
      url: params.url ??  null,
      notes: params.notes ?? null,
    });

    return result;
    
  } catch (err: any) {
    showToast(`${err}`, 'danger');
    throw err;
    
  }
}

// Update a password
export async function updatePassword(params: Omit<PasswordType,  'createdAt' | 'updatedAt'>) {
  
  try {
    const result: string = await invoke('update_password', {
      id: params.id,
      title: params.title,
      username: params.username,
      password: params.password,
      url: params.url ??  null,
      notes: params.notes ?? null,
    });

    return result;
    
  } catch (err: any) {
    showToast(`${err}`, 'danger');
    throw err;
    
  }
}

// Delete password
export async function deletePassword(id: string): Promise<void> {
    if (confirm('Are you sure you want to delete this password?')) {
        try {
          await invoke('delete_password', {id});
          showToast('Password deleted', 'success');
          
        } catch (error) {
          console.error('Failed to delete password: ', error);
          showToast('Password deleted', 'success');
          
        }
    }
}

// Check if database exists
export async function isDbExist(): Promise<boolean> {
  const db_exist = await invoke('is_db_exist');
  return db_exist as boolean;
}

// Delete database
export async function deleteDatabaseFolder(): Promise<void> {
  await invoke('delete_db_directory');
}