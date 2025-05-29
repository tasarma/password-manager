const toast = document.getElementById('toast') as HTMLElement;

export function showToast(message: string, type: string = ''): void {
    toast.textContent = message;
    toast.className = 'toast';
    if (type) toast.classList.add(type);
    toast.classList.add('show');

    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}
