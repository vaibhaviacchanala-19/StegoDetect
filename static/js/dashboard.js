document.addEventListener('DOMContentLoaded', function () {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const selectedFileName = document.getElementById('selectedFileName');
  const analyzeBtn = document.getElementById('analyzeBtn');

  const syncSelectionState = () => {
    const hasFile = fileInput && fileInput.files && fileInput.files.length > 0;
    if (selectedFileName) {
      selectedFileName.textContent = hasFile ? fileInput.files[0].name : 'No file selected';
    }
    if (analyzeBtn) {
      analyzeBtn.disabled = !hasFile;
    }
  };

  if (!dropzone || !fileInput) return;

  ['dragenter', 'dragover'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  fileInput.addEventListener('change', syncSelectionState);

  dropzone.addEventListener('drop', (event) => {
    const files = event.dataTransfer.files;
    if (files && files.length) {
      fileInput.files = files;
      syncSelectionState();
    }
  });

  syncSelectionState();
});
