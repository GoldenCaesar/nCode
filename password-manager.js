$(document).ready(function() {
  let siteCounter = 1;

  async function generateDeterministicPassword(masterPassword, siteName) {
    const combinedString = masterPassword + ":" + siteName;
    const encoder = new TextEncoder();
    const data = encoder.encode(combinedString);

    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
      return hashHex.substring(0, 16); // Truncate to 16 characters
    } catch (error) {
      console.error('Error generating password:', error);
      // Fallback or error indication if crypto fails
      // For now, returning a fixed string, but this should be handled more gracefully
      return "ErrorInCryptoGen";
    }
  }

  $('#addSiteButton').on('click', function() {
    siteCounter++;
    const newSiteInputHtml = `
      <div class="flex max-w-[480px] flex-wrap items-end gap-4 px-4 py-3">
        <label class="flex flex-col min-w-40 flex-1">
          <input
            placeholder="Site ${siteCounter}"
            class="site-input form-input flex w-full min-w-0 flex-1 resize-none overflow-hidden rounded-lg text-white focus:outline-0 focus:ring-0 border border-[#464d42] bg-[#20241e] focus:border-[#464d42] h-14 placeholder:text-[#a9b2a4] p-[15px] text-base font-normal leading-normal"
            value=""
          />
        </label>
      </div>
    `;
    $('#sitesContainer').append(newSiteInputHtml);
  });

  $('#processPasswordsButton').on('click', async function() {
    const masterPassword = $('#managerPassword').val();
    if (!masterPassword) {
      $('#passwordResultOutput').val('Please enter a Manager Password.');
      return;
    }

    let results = "";
    const siteInputs = $('#sitesContainer .site-input'); // Select all inputs with class 'site-input' within 'sitesContainer'

    if (siteInputs.length === 0) {
      $('#passwordResultOutput').val('Please add at least one site.');
      return;
    }

    let siteProcessedCount = 0;
    for (let i = 0; i < siteInputs.length; i++) {
      const siteName = $(siteInputs[i]).val();
      if (siteName) {
        try {
          const generatedPassword = await generateDeterministicPassword(masterPassword, siteName);
          results += `${siteName}: ${generatedPassword}\n`;
          siteProcessedCount++;
        } catch (error) {
          console.error(`Error processing site ${siteName}:`, error);
          results += `${siteName}: ErrorGeneratingPassword\n`;
        }
      }
    }

    if (siteProcessedCount === 0 && siteInputs.length > 0) {
      $('#passwordResultOutput').val('Please enter a site name in at least one of the site fields.');
      return;
    }

    $('#passwordResultOutput').val(results.trim());
  });
});
