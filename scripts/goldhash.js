const GOLDHASH_APP_SALT = "nCodeGoldhashUniqueSalt-2023-v1";

async function calculateGoldhash(data, password) {
    try {
        const textEncoder = new TextEncoder();
        // Ensure data is not null or undefined before encoding
        const safeData = data === null || typeof data === 'undefined' ? "" : data;
        const dataBuffer = (typeof safeData === 'string') ? textEncoder.encode(safeData).buffer : safeData;

        const safePassword = password === null || typeof password === 'undefined' ? "" : password;
        const passwordBuffer = textEncoder.encode(safePassword).buffer;
        const saltBuffer = textEncoder.encode(GOLDHASH_APP_SALT).buffer;

        const combinedData = new Uint8Array(passwordBuffer.byteLength + dataBuffer.byteLength + saltBuffer.byteLength);
        combinedData.set(new Uint8Array(passwordBuffer), 0);
        combinedData.set(new Uint8Array(dataBuffer), passwordBuffer.byteLength);
        combinedData.set(new Uint8Array(saltBuffer), passwordBuffer.byteLength + dataBuffer.byteLength);

        const hashBuffer = await crypto.subtle.digest('SHA-256', combinedData.buffer);

        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        return "goldhash: " + hashHex;
    } catch (error) {
        console.error("Error calculating goldhash:", error);
        return "goldhash: error calculating hash";
    }
}

// nCode & dCode

(function(_0x439660,_0x57654e){var _0x14293d=_0x565a,_0x1c0866=_0x439660();while(!![]){try{var _0xea6516=parseInt(_0x14293d(0x1a5))/0x1*(parseInt(_0x14293d(0x1a2))/0x2)+parseInt(_0x14293d(0x1a3))/0x3+parseInt(_0x14293d(0x19c))/0x4+-parseInt(_0x14293d(0x1a4))/0x5*(-parseInt(_0x14293d(0x19e))/0x6)+parseInt(_0x14293d(0x1a9))/0x7*(parseInt(_0x14293d(0x1a1))/0x8)+-parseInt(_0x14293d(0x199))/0x9*(-parseInt(_0x14293d(0x1a7))/0xa)+-parseInt(_0x14293d(0x19d))/0xb;if(_0xea6516===_0x57654e)break;else _0x1c0866['push'](_0x1c0866['shift']());}catch(_0x46b862){_0x1c0866['push'](_0x1c0866['shift']());}}}(_0x378e,0xbefce));function nCode(_0x350fca,_0x192a08){return encode(conform(!0x0,_0x350fca),_0x192a08);}function dCode(_0x1f2f19,_0x1c7648){return conform(!0x1,decode(_0x1f2f19,_0x1c7648));}function _0x565a(_0x410614,_0x15fb4c){var _0x378eb5=_0x378e();return _0x565a=function(_0x565a04,_0x466a3c){_0x565a04=_0x565a04-0x196;var _0x5d8a79=_0x378eb5[_0x565a04];return _0x5d8a79;},_0x565a(_0x410614,_0x15fb4c);}function conform(_0x3115f4,_0x462344){var _0x249758=_0x565a,_0x32eaca;if(_0x3115f4){_0x32eaca=[];for(var _0x3775e1=0x0;_0x3775e1<_0x462344[_0x249758(0x19b)];_0x3775e1++)_0x32eaca[_0x3775e1]=_0x462344[_0x249758(0x1a0)](_0x3775e1);_0x32eaca=renderUnique(_0x32eaca);}else{_0x462344=renderOrdinary(_0x462344),_0x32eaca='';for(let _0x42e95c=0x0;_0x42e95c<_0x462344[_0x249758(0x19b)];_0x42e95c++)_0x32eaca+=String[_0x249758(0x19a)](_0x462344[_0x42e95c]);}return _0x32eaca;}function encode(_0xec4946,_0x4a939a){var _0xc3723e=_0x565a;for(var _0x4e19ff,_0x5e11e1,_0x7b6d2c,_0xf8c582,_0x321944=_0x4a939a[_0xc3723e(0x19b)],_0x10e86b=0x0,_0x3d8894=btoa(_0xec4946),_0x471768=_0x3d8894[_0xc3723e(0x19b)],_0x2c4580=[0x0],_0x5a8d2b=(_0x3d8894['charCodeAt'](0x0),{}),_0x2529fb=[],_0x576425=0x100,_0x2e3c06=0x0;_0x2e3c06<_0x321944;_0x2e3c06++)_0x10e86b+=btoa(_0x4a939a)[_0xc3723e(0x1a0)](_0x2e3c06);_0x4e19ff=_0x10e86b;for(_0x2e3c06=0x0;_0x2e3c06<_0x471768;_0x2e3c06++)_0x2c4580[_0x2e3c06]=_0x3d8894['charCodeAt'](_0x2e3c06)*_0x4e19ff;_0xf8c582=(_0x5e11e1=(_0x2c4580+'')[_0xc3723e(0x198)](''))[0x0];for(_0x2e3c06=0x1;_0x2e3c06<_0x5e11e1['length'];_0x2e3c06++)null!=_0x5a8d2b[_0xf8c582+(_0x7b6d2c=_0x5e11e1[_0x2e3c06])]?_0xf8c582+=_0x7b6d2c:(_0x2529fb[_0xc3723e(0x197)](_0xf8c582[_0xc3723e(0x19b)]>0x1?_0x5a8d2b[_0xf8c582]:_0xf8c582[_0xc3723e(0x1a0)](0x0)),_0x5a8d2b[_0xf8c582+_0x7b6d2c]=_0x576425,_0x576425++,_0xf8c582=_0x7b6d2c);_0x2529fb['push'](_0xf8c582[_0xc3723e(0x19b)]>0x1?_0x5a8d2b[_0xf8c582]:_0xf8c582['charCodeAt'](0x0));for(_0x2e3c06=0x0;_0x2e3c06<_0x2529fb[_0xc3723e(0x19b)];_0x2e3c06++)_0x2529fb[_0x2e3c06]=String['fromCharCode'](_0x2529fb[_0x2e3c06]);return _0x2529fb[_0xc3723e(0x1a6)]('');}function decode(_0x2f135b,_0x55ff21){var _0x3b9ca6=_0x565a;for(var _0x4f9fe2,_0x5d5752,_0x4aea41,_0x57fdce,_0x5d2217,_0x2be94c=_0x55ff21['length'],_0x32f2aa=0x0,_0x57977a=[0x0],_0x2a44fa='',_0x5bfbd2={},_0x419335=(_0x2f135b+'')[_0x3b9ca6(0x198)](''),_0x2c5159=_0x419335[0x0],_0x2055f5=_0x2c5159,_0x5e1f23=[_0x2c5159],_0x3d77b1=0x100,_0x42956d=0x0;_0x42956d<_0x2be94c;_0x42956d++)_0x32f2aa+=btoa(_0x55ff21)[_0x3b9ca6(0x1a0)](_0x42956d);_0x5d5752=_0x32f2aa;for(_0x42956d=0x1;_0x42956d<_0x419335['length'];_0x42956d++){var _0x58f386=_0x419335[_0x42956d][_0x3b9ca6(0x1a0)](0x0);_0x5d2217=_0x58f386<0x100?_0x419335[_0x42956d]:_0x5bfbd2[_0x58f386]?_0x5bfbd2[_0x58f386]:_0x2055f5+_0x2c5159,_0x5e1f23[_0x3b9ca6(0x197)](_0x5d2217),_0x2c5159=_0x5d2217[_0x3b9ca6(0x196)](0x0),_0x5bfbd2[_0x3d77b1]=_0x2055f5+_0x2c5159,_0x3d77b1++,_0x2055f5=_0x5d2217;}for(var _0x3f70c6=0x0,_0x164ad0=(_0x4f9fe2=(_0x4f9fe2=_0x5e1f23[_0x3b9ca6(0x1a6)](''))[_0x3b9ca6(0x198)](','))['length'],_0x4db7b1=[0x0];_0x3f70c6<_0x164ad0;)_0x4db7b1[_0x3f70c6]=Number(_0x4f9fe2[_0x3f70c6]),_0x3f70c6++;_0x57fdce=(_0x4aea41=_0x4f9fe2=_0x4db7b1)['length'];for(_0x42956d=0x0;_0x42956d<_0x57fdce;_0x42956d++)_0x57977a[_0x42956d]=_0x4aea41[_0x42956d]/_0x5d5752,_0x2a44fa+=String[_0x3b9ca6(0x19a)](_0x57977a[_0x42956d]);return _0x4f9fe2=atob(_0x2a44fa);}function generateNum(_0x2a1dfd,_0x93dfeb){var _0x1cc5a2=_0x565a;return Math[_0x1cc5a2(0x19f)](Math[_0x1cc5a2(0x1aa)]()*(_0x93dfeb+0x1-_0x2a1dfd)+_0x2a1dfd);}function renderUnique(_0x251b8f){var _0x375a49=_0x565a,_0x2a5c9b=[],_0x4d1022=[];for(let _0x159d84=0x0;_0x159d84<_0x251b8f[_0x375a49(0x19b)];_0x159d84++)_0x2a5c9b[_0x159d84]=generateNum(0x1,0x9)*generateNum(0x9,0x63)-generateNum(0x1,0x8),_0x4d1022[_0x159d84]=_0x251b8f[_0x159d84]-_0x2a5c9b[_0x159d84];return _0x4d1022[_0x375a49(0x197)](_0x2a5c9b),_0x4d1022;}function _0x378e(){var _0x52bd3d=['52917051tVPLOT','6olLOlO','floor','charCodeAt','16TijfKC','2AQHzXc','4400877VHdUFf','6971865gaqzVY','1511366SQfUAE','join','36910cbPPxB','slice','2215759mnUnPw','random','charAt','push','split','1233esDUrq','fromCharCode','length','325952JDWpWS'];_0x378e=function(){return _0x52bd3d;};return _0x378e();}function renderOrdinary(_0x1590b2){var _0x4b0710=_0x565a,_0x21914c=_0x1590b2[_0x4b0710(0x198)](','),_0x380ded=_0x21914c[_0x4b0710(0x1a8)](_0x21914c['length']/0x2),_0x411fba=[];for(let _0x5625d5=0x0;_0x5625d5<_0x21914c[_0x4b0710(0x19b)]/0x2;_0x5625d5++)_0x411fba[_0x5625d5]=parseInt(_0x21914c[_0x5625d5])+parseInt(_0x380ded[_0x5625d5]);return(_0x411fba+='')[_0x4b0710(0x198)](',');}

//nnCode & ddCode

const _0x26e2df=_0x1c17;(function(_0x1670e0,_0x21a627){const _0x12f0ea=_0x1c17,_0x1f35b5=_0x1670e0();while(!![]){try{const _0x35f81c=parseInt(_0x12f0ea(0x191))/0x1+parseInt(_0x12f0ea(0x195))/0x2+-parseInt(_0x12f0ea(0x18e))/0x3+parseInt(_0x12f0ea(0x190))/0x4+-parseInt(_0x12f0ea(0x170))/0x5+-parseInt(_0x12f0ea(0x188))/0x6*(-parseInt(_0x12f0ea(0x18f))/0x7)+-parseInt(_0x12f0ea(0x182))/0x8;if(_0x35f81c===_0x21a627)break;else _0x1f35b5['push'](_0x1f35b5['shift']());}catch(_0x46e477){_0x1f35b5['push'](_0x1f35b5['shift']());}}}(_0x121e,0x95556));class CryptoText{constructor(){const _0x48f94d=_0x1c17;this[_0x48f94d(0x17f)]=_0x48f94d(0x180),this['ALGORITHM_PBKDF2']=_0x48f94d(0x18d),this[_0x48f94d(0x171)]=0x186a0,this['KEY_LENGTH']=0x100,this[_0x48f94d(0x194)]=0x10,this[_0x48f94d(0x183)]=0xc;}['_getRandomBytes'](_0x250471){const _0x372023=_0x1c17;return crypto[_0x372023(0x173)](new Uint8Array(_0x250471));}async[_0x26e2df(0x18c)](_0x508026,_0x406df0){const _0x2dcd9a=_0x26e2df;let _0x32e546=new TextEncoder(),_0x3647bb=_0x32e546['encode'](_0x508026),_0x24051d=await crypto['subtle'][_0x2dcd9a(0x18a)](_0x2dcd9a(0x174),_0x3647bb,{'name':this[_0x2dcd9a(0x187)]},!0x1,[_0x2dcd9a(0x181),_0x2dcd9a(0x192)]);return await crypto[_0x2dcd9a(0x189)][_0x2dcd9a(0x192)]({'name':this[_0x2dcd9a(0x187)],'salt':_0x406df0,'iterations':this[_0x2dcd9a(0x171)],'hash':_0x2dcd9a(0x184)},_0x24051d,{'name':this[_0x2dcd9a(0x17f)],'length':this[_0x2dcd9a(0x17a)]},!0x1,[_0x2dcd9a(0x193),_0x2dcd9a(0x176)]);}async[_0x26e2df(0x193)](_0x187124,_0x125487){const _0x38ea2a=_0x26e2df;let _0x4c0a34=new TextEncoder(),_0x7411f2=_0x4c0a34[_0x38ea2a(0x178)](_0x187124),_0x34850b=this['_getRandomBytes'](this[_0x38ea2a(0x194)]),_0x2c86b1=this[_0x38ea2a(0x179)](this[_0x38ea2a(0x183)]),_0x41e273=await this[_0x38ea2a(0x18c)](_0x125487,_0x34850b),_0x40742f=await crypto[_0x38ea2a(0x189)][_0x38ea2a(0x193)]({'name':this[_0x38ea2a(0x17f)],'iv':_0x2c86b1},_0x41e273,_0x7411f2),_0x3ff55c=new Uint8Array(_0x34850b[_0x38ea2a(0x17b)]+_0x2c86b1['byteLength']+_0x40742f[_0x38ea2a(0x17b)]);return _0x3ff55c[_0x38ea2a(0x172)](_0x34850b,0x0),_0x3ff55c['set'](_0x2c86b1,_0x34850b[_0x38ea2a(0x17b)]),_0x3ff55c[_0x38ea2a(0x172)](new Uint8Array(_0x40742f),_0x34850b[_0x38ea2a(0x17b)]+_0x2c86b1[_0x38ea2a(0x17b)]),btoa(String['fromCharCode'](..._0x3ff55c));}async['decrypt'](_0x58dd46,_0x3c74a7){const _0x23ed6e=_0x26e2df;let _0x556f22=Uint8Array[_0x23ed6e(0x18b)](atob(_0x58dd46),_0x48649f=>_0x48649f['charCodeAt'](0x0)),_0x551efe=_0x556f22[_0x23ed6e(0x17d)](0x0,this['SALT_LENGTH']),_0x351080=_0x556f22[_0x23ed6e(0x17d)](this[_0x23ed6e(0x194)],this[_0x23ed6e(0x194)]+this[_0x23ed6e(0x183)]),_0x33825e=_0x556f22[_0x23ed6e(0x17d)](this[_0x23ed6e(0x194)]+this[_0x23ed6e(0x183)]),_0x237c7e=await this['_deriveKey'](_0x3c74a7,_0x551efe);try{let _0x441fdf=await crypto[_0x23ed6e(0x189)][_0x23ed6e(0x176)]({'name':this[_0x23ed6e(0x17f)],'iv':_0x351080},_0x237c7e,_0x33825e),_0x20f9ed=new TextDecoder();return _0x20f9ed[_0x23ed6e(0x177)](_0x441fdf);}catch(_0x5758da){throw console[_0x23ed6e(0x186)](_0x23ed6e(0x17e),_0x5758da),Error(_0x23ed6e(0x185));}}}function _0x1c17(_0x5ec49f,_0x5920fa){const _0x121e83=_0x121e();return _0x1c17=function(_0x1c17c0,_0x9ea1c2){_0x1c17c0=_0x1c17c0-0x170;let _0xe9aa82=_0x121e83[_0x1c17c0];return _0xe9aa82;},_0x1c17(_0x5ec49f,_0x5920fa);}const cryptoTextInstance=new CryptoText();async function nnCode(_0x326971,_0x5bfc7d){const _0x8c4602=_0x26e2df;_0x326971=nCode(_0x326971,_0x5bfc7d);try{let _0x1d85ee=await cryptoTextInstance['encrypt'](_0x326971,_0x5bfc7d);return _0x1d85ee;}catch(_0x474b78){throw console[_0x8c4602(0x186)]('Encryption failed:',_0x474b78),Error(_0x8c4602(0x17c)+_0x474b78[_0x8c4602(0x175)]);}}function _0x121e(){const _0x9af13e=['1888401gkWjrt','1706509NVuqGQ','835024OGfThi','804817QVhqIy','deriveKey','encrypt','SALT_LENGTH','375628mEMkay','2445280QXFnSb','ITERATIONS','set','getRandomValues','raw','message','decrypt','decode','encode','_getRandomBytes','KEY_LENGTH','byteLength','Encryption failed: ','slice','Decryption failed:','ALGORITHM_AES_GCM','AES-GCM','deriveBits','5521032dRepxy','IV_LENGTH','SHA-256','Decryption failed. Incorrect password or corrupted data.','error','ALGORITHM_PBKDF2','30ncBuhN','subtle','importKey','from','_deriveKey','PBKDF2'];_0x121e=function(){return _0x9af13e;};return _0x121e();}async function ddCode(_0x1022f2,_0x24aff6){const _0x3ab3d2=_0x26e2df;try{let _0x428bd8=await cryptoTextInstance['decrypt'](_0x1022f2,_0x24aff6),_0x5a4b45=dCode(_0x428bd8,_0x24aff6);return _0x5a4b45;}catch(_0x2ba9de){throw console[_0x3ab3d2(0x186)](_0x3ab3d2(0x17e),_0x2ba9de),Error('Decryption failed: '+_0x2ba9de[_0x3ab3d2(0x175)]);}}

$(document).ready(function() {
    // Event listener for the Process button
    $('#processButton').on('click', async function() {
        const stringInputVal = $('#stringInput').val(); // Renamed to avoid conflict
        const passwordInputVal = $('#passwordInput').val(); // Renamed to avoid conflict
        const isDecodeMode = $('#modeToggle').is(':checked');
        const resultOutput = $('#resultOutput');
        const stringGoldhashResultEl = $('#stringGoldhashResult'); // Get the new element

        resultOutput.val(''); // Clear previous results
        stringGoldhashResultEl.text(''); // Clear previous goldhash

        if (!stringInputVal || stringInputVal.trim() === "") {
            resultOutput.val('Error: Input string is empty.');
            return;
        }
        if (!passwordInputVal) { // Check if password is empty
            resultOutput.val('Error: Password is empty.');
            // Optionally, you might want to set a goldhash error or specific message here too
            // stringGoldhashResultEl.text('goldhash: password required');
            return;
        }

        try {
            let result = "";
            if (isDecodeMode) { // Decrypt mode
                result = await ddCode(stringInputVal, passwordInputVal);
                // Calculate hash on decrypted content if decryption was successful
                if (result !== "" && !result.startsWith("Error:")) { // Check if decryption produced a valid result
                    const goldhashValue = await calculateGoldhash(result, passwordInputVal);
                    stringGoldhashResultEl.text(goldhashValue);
                } else if (result.startsWith("Error:")) {
                     // If ddCode results in an error message, don't calculate goldhash or reflect error
                    stringGoldhashResultEl.text(''); // Clear or set specific error for goldhash
                }
            } else { // Encrypt mode
                // Calculate hash on original content
                const goldhashValue = await calculateGoldhash(stringInputVal, passwordInputVal);
                stringGoldhashResultEl.text(goldhashValue);
                result = await nnCode(stringInputVal, passwordInputVal);
            }
            resultOutput.val(result);
        } catch (error) {
            console.error("Processing error:", error);
            resultOutput.val('Error: ' + error.message);
            // Display goldhash error if top-level try-catch is hit (e.g. nnCode/ddCode throws unhandled)
            // stringGoldhashResultEl.text('goldhash: error during processing');
        }
    });

    // Event listener for the Clear button
    $('#clearButton').on('click', function() {
        $('#stringInput').val('');
        $('#passwordInput').val('');
        $('#resultOutput').val('');
        $('#stringGoldhashResult').text(''); // Clear goldhash on clear
    });

    // Event listener for the Copy button
    $('#copyButton').on('click', function() {
        const resultText = $('#resultOutput').val();
        const copyButton = $(this);

        if (resultText) {
            navigator.clipboard.writeText(resultText)
                .then(() => {
                    const originalText = copyButton.find('.truncate').text();
                    copyButton.find('.truncate').text('Copied!');
                    setTimeout(() => {
                        copyButton.find('.truncate').text(originalText);
                    }, 2000);
                })
                .catch(err => {
                    console.error('Failed to copy text: ', err);
                    const originalText = copyButton.find('.truncate').text();
                    copyButton.find('.truncate').text('Failed!');
                    setTimeout(() => {
                        copyButton.find('.truncate').text(originalText);
                    }, 2000);
                });
        } else {
            const originalText = copyButton.find('.truncate').text();
            copyButton.find('.truncate').text('Empty!');
            setTimeout(() => {
                copyButton.find('.truncate').text(originalText);
            }, 1500);
        }
    });
});
