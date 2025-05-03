document.addEventListener('DOMContentLoaded', function() {
  console.log('Upload.js loaded successfully');
  
  // Get form elements
  const uploadForm = document.getElementById('uploadForm');
  const fileInput = document.querySelector('input[type="file"]');
  const uploadButton = document.getElementById('uploadButton');
  
  // File input change handler
  if (fileInput) {
    fileInput.addEventListener('change', function() {
      console.log('File selected:', fileInput.files[0]?.name || 'No file');
      if (fileInput.files.length > 0) {
        uploadButton.disabled = false;
      }
    });
  }
  
  // Form submission
  if (uploadForm) {
    uploadForm.addEventListener('submit', async function(e) {
      e.preventDefault();
      console.log('Form submitted');
      
      if (!fileInput || !fileInput.files.length) {
        console.error('No file selected');
        return;
      }
      
      const file = fileInput.files[0];
      console.log('File selected:', file.name);
      
      // Create FormData object
      const formData = new FormData();
      formData.append('file', file);
      
      // Add CSRF token if available
      const csrfToken = document.getElementById('csrfToken');
      if (csrfToken && csrfToken.value) {
        formData.append('csrfToken', csrfToken.value);
      }
      
      console.log('Uploading file to /api/upload');
      
      try {
        const response = await fetch('/api/upload', {
          method: 'POST',
          body: formData
        });
        
        console.log('Response status:', response.status);
        
        if (response.ok) {
          let result;
          const contentType = response.headers.get('content-type');
          
          if (contentType && contentType.includes('application/json')) {
            try {
              result = await response.json();
            } catch (parseError) {
              console.error('Error parsing JSON response:', parseError);
              result = { message: 'File uploaded but response could not be parsed' };
            }
          } else {
            // Handle non-JSON responses
            const text = await response.text();
            result = { message: 'File uploaded successfully', responseText: text };
          }
          
          console.log('Upload successful:', result);
          alert('File uploaded successfully!');
          
          // Reset form
          uploadForm.reset();
          if (uploadButton) {
            uploadButton.disabled = true;
          }
        } else {
          console.error('Upload failed with status:', response.status);
          
          let errorMessage = `Error ${response.status}: `;
          
          try {
            const errorData = await response.json();
            errorMessage += errorData.error || 'Unknown error';
            console.error('Error details:', errorData);
          } catch (e) {
            // If response is not JSON
            const text = await response.text();
            errorMessage += text || 'Unknown error';
          }
          
          alert('Upload failed: ' + errorMessage);
        }
      } catch (error) {
        console.error('Upload error:', error);
        alert('Upload error: ' + error.message);
      }
    });
  } else {
    console.error('Upload form not found');
  }
});