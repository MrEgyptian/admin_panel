document.addEventListener('DOMContentLoaded', () => {
	const form = document.getElementById('login-form');
	if (!form) {
		return;
	}

	const usernameInput = form.elements.namedItem('username');
	const passwordInput = form.elements.namedItem('password');
	const submitButton = form.querySelector('button[type="submit"]');
	const inputs = [usernameInput, passwordInput].filter((input) => input instanceof HTMLInputElement);

	if (usernameInput instanceof HTMLInputElement) {
		usernameInput.focus();
	}

	inputs.forEach((input) => {
		input.addEventListener('input', () => {
			input.classList.remove('input-error');
			if (submitButton) {
				submitButton.disabled = false;
				submitButton.textContent = submitButton.dataset.originalText || 'Sign In';
			}
		});
	});

	form.addEventListener('submit', (event) => {
		let hasError = false;
		inputs.forEach((input) => {
			const trimmed = input.value.trim();
			input.value = trimmed;
			if (!trimmed) {
				input.classList.add('input-error');
				if (!hasError) {
					input.focus();
				}
				hasError = true;
			}
		});

		if (hasError) {
			event.preventDefault();
			return;
		}

		if (submitButton) {
			submitButton.dataset.originalText = submitButton.textContent ?? '';
			submitButton.disabled = true;
			submitButton.textContent = 'Signing in…';
		}
	});
});
