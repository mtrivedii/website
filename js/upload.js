async function getSasToken(filename) {
  try {
    // Call the Azure Function through the configured route
    const response = await fetchWithTimeout(
      `/api/getSasToken?blobName=${encodeURIComponent(filename)}`, 
      {
        headers: {
          "Accept": "application/json"  // Request JSON explicitly
        }
      },
      10000
    );
    
    if (!response.ok) {
      let errorText = await response.text();
      try {
        // Try to parse as JSON first
        const errorJson = JSON.parse(errorText);
        throw new Error(errorJson.error || errorJson.details || `Failed to get SAS token: ${response.status}`);
      } catch (parseError) {
        // If it's not valid JSON, use the raw text (truncated)
        throw new Error(`Failed to get SAS token: ${errorText.substring(0, 100)}`);
      }
    }
    
    let data;
    const contentType = response.headers.get('content-type');
    const responseText = await response.text();
    
    // Try to extract JSON from the response, even if content type is incorrect
    try {
      // First try direct JSON parsing
      data = JSON.parse(responseText);
    } catch (error) {
      // If direct parsing fails, try to extract JSON from potential HTML
      try {
        // Look for JSON-like content in the response
        const jsonMatch = responseText.match(/\{.*\}/s);
        if (jsonMatch) {
          data = JSON.parse(jsonMatch[0]);
        } else {
          throw new Error(`Could not find JSON in response`);
        }
      } catch (nestedError) {
        throw new Error(`Response is not valid JSON: ${contentType}`);
      }
    }
    
    // Validate response data
    if (!data || !data.sasUrl) {
      throw new Error('Invalid SAS token response: missing sasUrl');
    }
    
    return data;
  } catch (error) {
    console.error('Error getting SAS token:', error);
    throw error;
  }
}