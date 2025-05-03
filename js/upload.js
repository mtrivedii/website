document.addEventListener('DOMContentLoaded', function() {
    // Get form elements
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.querySelector('input[type="file"]');
    const uploadButton = document.getElementById('uploadButton');
    const csrfToken = document.getElementById('csrfToken');
    
    console.log('Upload.js loaded successfully');
    
    // Enable file selection
    if (fileInput) {
      fileInput.addEventListener('change', function() {
        if (fileInput.files.length > 0) {
          // Show file details
          const file = fileInput.files[0];
          if (document.getElementById('fileDetails')) {
            document.getElementById('fileDetails').style.display = 'block';
          }
          
          // Enable upload button
          if (uploadButton) {
            uploadButton.disabled = false;
          }
          
          console.log('File selected:', file.name);
        }
      });
    } else {
      console.error('File input element not found');
    }
    
    // Handle form submission
    if (uploadForm) {
      uploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        console.log('Form submitted');
        
        if (!fileInput || !fileInput.files.length) {
          console.error('No file selected');
          return;
        }
        
        const file = fileInput.files[0];
        
        // Create FormData object
        const formData = new FormData();
        formData.append('file', file);
        
        // Add CSRF token if available
        if (csrfToken && csrfToken.value) {
          formData.append('csrfToken', csrfToken.value);
        }
        
        try {
          console.log('Uploading file to /api/upload');
          const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
          });
          
          if (response.ok) {
            const result = await response.json();
            console.log('Upload successful:', result);
            
            // Show success message
            if (document.getElementById('uploadMessage')) {
              document.getElementById('uploadMessage').textContent = 'File uploaded successfully!';
            }
            
            // Reset form
            uploadForm.reset();
            if (uploadButton) {
              uploadButton.disabled = true;
            }
            if (document.getElementById('fileDetails')) {
              document.getElementById('fileDetails').style.display = 'none';
            }
          } else {
            const error = await response.json();
            console.error('Upload failed:', error);
            
            // Show error message
            if (document.getElementById('uploadMessage')) {
              document.getElementById('uploadMessage').textContent = 'Upload failed: ' + (error.error || 'Unknown error');
            }
          }
        } catch (error) {
          console.error('Upload error:', error);
          
          // Show error message
          if (document.getElementById('uploadMessage')) {
            document.getElementById('uploadMessage').textContent = 'Upload error: ' + error.message;
          }
        }
      });
    } else {
      console.error('Upload form not found');
    }
  });