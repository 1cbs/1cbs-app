document.addEventListener('DOMContentLoaded', function() {

    // --- Animated Star Background ---
    const starBackground = document.getElementById('star-background');
    if (starBackground) {
        const numberOfStars = 150;
        for (let i = 0; i < numberOfStars; i++) {
            let star = document.createElement('div');
            star.className = 'star';
            star.style.top = `${Math.random() * 100}%`;
            star.style.left = `${Math.random() * 100}%`;
            star.style.width = `${Math.random() * 3}px`;
            star.style.height = star.style.width;
            star.style.animationDelay = `${Math.random() * 5}s`;
            star.style.animationDuration = `${Math.random() * 5 + 5}s`;
            starBackground.appendChild(star);
        }
    }

    // --- Modal Handling ---
    window.openModal = function(modalId, videoSrc) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'block';
            if (modalId === 'videoPlayerModal' && videoSrc) {
                const videoPlayer = document.getElementById('videoPlayer');
                if(videoPlayer) {
                    videoPlayer.src = videoSrc;
                    videoPlayer.play();
                }
            }
        }
    };

    window.closeModal = function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.style.display = 'none';
            if (modalId === 'videoPlayerModal') {
                const videoPlayer = document.getElementById('videoPlayer');
                 if(videoPlayer) {
                    videoPlayer.pause();
                    videoPlayer.src = ''; // Clear src to stop background loading
                }
            }
        }
    };

    // Close modal if user clicks outside of it
    window.onclick = function(event) {
        if (event.target.classList.contains('modal')) {
            closeModal(event.target.id);
        }
    };

    // --- Password Visibility Toggle ---
    window.togglePassword = function(button) {
        const input = button.previousElementSibling;
        const icon = button.querySelector('i');
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    };

    // --- Drag and Drop Upload ---
    function setupDropZone(zoneId, inputId) {
        const dropZone = document.getElementById(zoneId);
        const fileInput = document.getElementById(inputId);

        if (!dropZone || !fileInput) return;
        
        const uploadUrl = fileInput.dataset.uploadUrl;
        if (!uploadUrl) return;

        // Open file dialog when drop zone is clicked
        dropZone.addEventListener('click', () => fileInput.click());

        // Highlight drop zone when file is dragged over
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });

        // Handle file drop
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length) {
                fileInput.files = files;
                handleUpload(files, uploadUrl);
            }
        });
        
        // Handle file selection from dialog
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                handleUpload(fileInput.files, uploadUrl);
            }
        });
    }

    function handleUpload(files, url) {
        const formData = new FormData();
        for(let i = 0; i < files.length; i++) {
            formData.append('file', files[i]);
        }

        fetch(url, {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            console.log('Upload success:', data);
            // Reload the page to show the new file
            window.location.reload(); 
        })
        .catch(error => {
            console.error('Upload error:', error);
            alert('An error occurred during upload.');
        });
    }

    // Initialize drop zones for each page if they exist
    setupDropZone('file-drop-zone', 'file-input');
    setupDropZone('video-drop-zone', 'video-input');
    setupDropZone('anime-drop-zone', 'anime-input');

});
