$(document).ready(function() {
  let siteCounter = 1;

  async function generateDeterministicPassword(masterPassword, siteName) {
    const combinedString = masterPassword + ":" + siteName;
    const encoder = new TextEncoder();
    const data = encoder.encode(combinedString);

    try {
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer)); // 32 bytes

      const lower = 'abcdefghijklmnopqrstuvwxyz';
      const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      const numbers = '0123456789';
      const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>/?';

      const allChars = lower + upper + numbers + symbols;

      let password_chars = [];

      if (hashArray.length >= 4) {
          password_chars.push(lower[hashArray[0] % lower.length]);
          password_chars.push(upper[hashArray[1] % upper.length]);
          password_chars.push(numbers[hashArray[2] % numbers.length]);
          password_chars.push(symbols[hashArray[3] % symbols.length]);
      } else {
          password_chars.push(lower[0]);
          password_chars.push(upper[0]);
          password_chars.push(numbers[0]);
          password_chars.push(symbols[0]);
      }

      let fillHashIndex = 4; // Start from the 5th byte of the hash (index 4)
      while (password_chars.length < 16) {
          if (fillHashIndex >= hashArray.length) {
              fillHashIndex = 0;
          }
          password_chars.push(allChars[hashArray[fillHashIndex] % allChars.length]);
          fillHashIndex++;
      }

      let shuffleRandIndex = Math.floor(hashArray.length / 2);
      for (let i = password_chars.length - 1; i > 0; i--) {
          if (shuffleRandIndex >= hashArray.length) {
              shuffleRandIndex = 0;
          }
          const randByteForShuffle = hashArray[shuffleRandIndex];
          shuffleRandIndex++;

          const j = randByteForShuffle % (i + 1);
          [password_chars[i], password_chars[j]] = [password_chars[j], password_chars[i]];
      }

      return password_chars.join('');

    } catch (error) {
      console.error('Error generating password (v2):', error);
      return "ErrCryptoV2!#%16";
    }
  }

  $('#addSiteButton').on('click', function() {
    siteCounter++;
    const newSiteInputHtml = `
      <div class="site-input-wrapper flex max-w-[480px] flex-wrap items-end gap-4 px-4 py-3">
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

  $('#clearPasswordsButton').on('click', function() {
    // Clear Manager Password
    $('#managerPassword').val('');

    // Clear Result Output
    $('#passwordResultOutput').val('');

    // Clear all site inputs
    const siteInputs = $('#sitesContainer .site-input');
    siteInputs.each(function() {
      $(this).val('');
    });

    // Handle Site Input Elements
    const sitesContainer = $('#sitesContainer');
    // Get all div wrappers for site inputs. These are direct children of sitesContainer.
    // Based on the HTML structure:
    // <div id="sitesContainer">
    //   <div class="flex max-w-[480px] flex-wrap items-end gap-4 px-4 py-3"> <!-- Wrapper for Site 1 -->
    //     <label class="flex flex-col min-w-40 flex-1">
    //       <input placeholder="Site 1" class="site-input ..."/>
    //     </label>
    //   </div>
    //   <!-- Dynamically added sites follow the same wrapper structure -->
    // </div>
    // So, we target these direct child divs for removal.
    const siteInputWrappers = sitesContainer.children('.site-input-wrapper');

    // Remove all dynamically added site input wrappers.
    siteInputWrappers.remove();

    // Reset siteCounter
    siteCounter = 1;
    // The placeholder for the first site input is static ("Site 1") and does not need to be updated.
  });
});
