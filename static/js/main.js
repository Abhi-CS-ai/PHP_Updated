document.addEventListener('DOMContentLoaded', function () {
    // Theme toggle
    const html = document.documentElement;
    const themeToggleBtn = document.getElementById('theme-toggle');

    if (localStorage.getItem('theme') === 'dark') {
        html.classList.add('dark');
    }

    themeToggleBtn.addEventListener('click', () => {
        html.classList.toggle('dark');
        localStorage.setItem('theme', html.classList.contains('dark') ? 'dark' : 'light');
    });

    // Mobile menu toggle
    const mobileBtn = document.getElementById('mobile-menu-button');
    const mobileMenu = document.getElementById('mobile-menu');
    if (mobileBtn && mobileMenu) {
        mobileBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('hidden');
        });
    }

    // Flash messages auto-dismiss
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(function (message) {
        setTimeout(() => {
            message.classList.add('opacity-0');
            setTimeout(() => message.remove(), 300);
        }, 5000);
    });

    // Scan Page - Tab switch
    const fileTabBtn = document.getElementById('fileTabButton');
    const urlTabBtn = document.getElementById('urlTabButton');
    const fileTab = document.getElementById('fileTab');
    const urlTab = document.getElementById('urlTab');

    if (fileTabBtn && urlTabBtn && fileTab && urlTab) {
        fileTabBtn.addEventListener('click', () => {
            fileTab.classList.remove('hidden');
            urlTab.classList.add('hidden');

            fileTabBtn.classList.add('text-blue-600', 'dark:text-blue-400', 'border-b-2', 'border-blue-600', 'dark:border-blue-400');
            fileTabBtn.classList.remove('text-gray-600', 'dark:text-gray-400');

            urlTabBtn.classList.remove('text-blue-600', 'dark:text-blue-400', 'border-b-2', 'border-blue-600', 'dark:border-blue-400');
            urlTabBtn.classList.add('text-gray-600', 'dark:text-gray-400');
        });

        urlTabBtn.addEventListener('click', () => {
            urlTab.classList.remove('hidden');
            fileTab.classList.add('hidden');

            urlTabBtn.classList.add('text-blue-600', 'dark:text-blue-400', 'border-b-2', 'border-blue-600', 'dark:border-blue-400');
            urlTabBtn.classList.remove('text-gray-600', 'dark:text-gray-400');

            fileTabBtn.classList.remove('text-blue-600', 'dark:text-blue-400', 'border-b-2', 'border-blue-600', 'dark:border-blue-400');
            fileTabBtn.classList.add('text-gray-600', 'dark:text-gray-400');
        });
    }

    // File upload interaction
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('file');
    const browseButton = document.getElementById('browseButton');
    const fileInfo = document.getElementById('fileInfo');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const removeFileBtn = document.getElementById('removeFile');
    const fileSubmitButton = document.getElementById('fileSubmitButton');

    if (dropZone && fileInput && browseButton && fileSubmitButton) {
        function formatFileSize(bytes) {
            if (bytes < 1024) return `${bytes} B`;
            else if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
            else return `${(bytes / 1048576).toFixed(1)} MB`;
        }

        function handleFile(file) {
            if (file.name.endsWith('.php')) {
                fileName.textContent = file.name;
                fileSize.textContent = formatFileSize(file.size);
                fileInfo.classList.remove('hidden');

                fileSubmitButton.classList.remove('bg-gray-400', 'cursor-not-allowed');
                fileSubmitButton.classList.add('bg-blue-600', 'hover:bg-blue-700');
                fileSubmitButton.disabled = false;
            } else {
                alert('Only PHP files are allowed.');
                fileInput.value = '';
            }
        }

        browseButton.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleFile(fileInput.files[0]);
            }
        });

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('ring-2', 'ring-blue-400');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('ring-2', 'ring-blue-400');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('ring-2', 'ring-blue-400');
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                handleFile(e.dataTransfer.files[0]);
            }
        });

        if (removeFileBtn) {
            removeFileBtn.addEventListener('click', () => {
                fileInput.value = '';
                fileInfo.classList.add('hidden');
                fileSubmitButton.disabled = true;
                fileSubmitButton.classList.add('bg-gray-400', 'cursor-not-allowed');
                fileSubmitButton.classList.remove('bg-blue-600', 'hover:bg-blue-700');
            });
        }
    }

    // Help modal
    const helpButton = document.getElementById('helpButton');
    const helpModal = document.getElementById('helpModal');
    const closeHelpModal = document.getElementById('closeHelpModal');

    if (helpButton && helpModal && closeHelpModal) {
        helpButton.addEventListener('click', () => {
            helpModal.classList.remove('hidden');
            document.body.style.overflow = 'hidden';
        });

        closeHelpModal.addEventListener('click', () => {
            helpModal.classList.add('hidden');
            document.body.style.overflow = 'auto';
        });

        helpModal.addEventListener('click', (e) => {
            if (e.target === helpModal) {
                helpModal.classList.add('hidden');
                document.body.style.overflow = 'auto';
            }
        });
    }

    // Scan results toggle
    const toggleDetailsBtns = document.querySelectorAll('.toggle-details');
    toggleDetailsBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const details = btn.closest('.vulnerability-item').querySelector('.vulnerability-details');
            const icon = btn.querySelector('.details-icon');
            details.classList.toggle('hidden');
            icon.classList.toggle('fa-chevron-down');
            icon.classList.toggle('fa-chevron-up');
        });
    });

    // Scan result filter
    const filterBtns = document.querySelectorAll('.filter-btn');
    const vulnerabilityItems = document.querySelectorAll('.vulnerability-item');
    if (filterBtns.length && vulnerabilityItems.length) {
        filterBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const severity = btn.getAttribute('data-severity');
                vulnerabilityItems.forEach(item => {
                    const match = severity === 'all' || item.getAttribute('data-severity') === severity;
                    item.classList.toggle('hidden', !match);
                });
                filterBtns.forEach(b => b.classList.remove('ring-2', 'ring-gray-400', 'dark:ring-gray-500'));
                btn.classList.add('ring-2', 'ring-gray-400', 'dark:ring-gray-500');
            });
        });
    }

    // History search
    const searchInput = document.getElementById('searchInput');
    const scansTable = document.getElementById('scansTable');
    if (searchInput && scansTable) {
        searchInput.addEventListener('keyup', () => {
            const searchTerm = searchInput.value.toLowerCase();
            const rows = scansTable.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const source = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
                const type = row.querySelector('td:nth-child(3)').textContent.toLowerCase();
                row.style.display = source.includes(searchTerm) || type.includes(searchTerm) ? '' : 'none';
            });
        });
    }
});
