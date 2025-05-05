document.addEventListener('DOMContentLoaded', function() {
  const fileInput = document.getElementById('file');
  const filenameDisplay = document.getElementById('filename-display');
  const fileDetails = document.getElementById('fileDetails');
  const fileSize = document.getElementById('fileSize');
  const fileType = document.getElementById('fileType');
  const uploadButton = document.getElementById('uploadButton');
  const uploadForm = document.getElementById('uploadForm');
  const uploadMessage = document.getElementById('uploadMessage');
  const progressContainer = document.getElementById('uploadProgress');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');

  // File selection handler
  fileInput.addEventListener('change', function() {
    if (this.files.length === 0) {
      filenameDisplay.textContent = 'No file selected';
      fileDetails.style.display = 'none';
      uploadButton.disabled = true;
      return;
    }

    const file = this.files[0];
    filenameDisplay.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    fileType.textContent = file.type || 'Unknown';
    fileDetails.style.display = 'block';

    // Validate file type and size
    const validExtensions = ['.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.csv', '.json', '.xml'];
    const maxSize = 10 * 1024 * 1024; // 10MB

    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    const isValidType = validExtensions.includes(fileExtension);
    const isValidSize = file.size <= maxSize;

    if (!isValidType) {
      uploadMessage.textContent = 'Error: File type not allowed';
      uploadMessage.className = 'warning';
      uploadButton.disabled = true;
    } else if (!isValidSize) {
      uploadMessage.textContent = 'Error: File exceeds 10MB size limit';
      uploadMessage.className = 'warning';
      uploadButton.disabled = true;
    } else {
      uploadMessage.textContent = '';
      uploadButton.disabled = false;
    }
  });

  // Form submission handler (now uses SAS + direct upload)
  uploadForm.addEventListener('submit', async function(e) {
    e.preventDefault();

    const file = fileInput.files[0];
    if (!file) return;

    progressContainer.style.display = 'block';
    uploadButton.disabled = true;
    uploadMessage.textContent = 'Requesting upload URL...';
    uploadMessage.className = '';

    try {
      // 1. Request SAS URL from backend
      const response = await fetch(`/api/getSasToken?blobName=${encodeURIComponent(file.name)}`);
      if (!response.ok) throw new Error('Failed to get SAS token');
      const { sasUrl } = await response.json();

      // 2. Upload the file directly to Blob Storage with progress
      const xhr = new XMLHttpRequest();
      xhr.upload.addEventListener('progress', function(e) {
        if (e.lengthComputable) {
          const percentComplete = Math.round((e.loaded / e.total) * 100);
          progressBar.style.width = percentComplete + '%';
          progressText.textContent = percentComplete + '%';
        }
      });

      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          if (xhr.status >= 200 && xhr.status < 300) {
            uploadMessage.textContent = 'Upload successful!';
            uploadMessage.className = 'success';
            setTimeout(() => {
              uploadForm.reset();
              filenameDisplay.textContent = 'No file selected';
              fileDetails.style.display = 'none';
              progressContainer.style.display = 'none';
              progressBar.style.width = '0%';
              progressText.textContent = '0%';
              uploadButton.disabled = true;
            }, 2000);
          } else {
            let errorMsg = 'Upload failed: Server returned status ' + xhr.status;
            if (xhr.statusText) errorMsg = 'Upload failed: ' + xhr.statusText;
            uploadMessage.textContent = errorMsg;
            uploadMessage.className = 'warning';
            uploadButton.disabled = false;
            progressContainer.style.display = 'none';
          }
        }
      };

      xhr.open('PUT', sasUrl, true);
      xhr.setRequestHeader('x-ms-blob-type', 'BlockBlob');
      xhr.setRequestHeader('Content-Type', file.type);
      xhr.send(file);

    } catch (error) {
      progressContainer.style.display = 'none';
      uploadMessage.textContent = 'Upload error: ' + error.message;
      uploadMessage.className = 'warning';
      uploadButton.disabled = false;
    }
  });

  // Helper function to format file size
  function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
});
