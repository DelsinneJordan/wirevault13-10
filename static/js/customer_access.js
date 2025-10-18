(function () {
    document.addEventListener('DOMContentLoaded', function () {
        const scanButton = document.querySelector('[data-action="scan-qr"]');
        const fileInput = document.getElementById('qr-input');
        const statusEl = document.querySelector('[data-scan-status]');

        if (!scanButton || !fileInput) {
            return;
        }

        const barcodeSupported = 'BarcodeDetector' in window;
        const jsQRSupported = typeof window.jsQR === 'function';
        if (!barcodeSupported && !jsQRSupported) {
            if (statusEl) {
                statusEl.textContent = 'QR scanning is not supported on this device. You can still type the QR code short ID above.';
            }
            scanButton.classList.add('is-disabled');
            scanButton.disabled = true;
        }

        scanButton.addEventListener('click', function () {
            if (!barcodeSupported && !jsQRSupported) {
                return;
            }
            clearStatus();
            fileInput.click();
        });

        fileInput.addEventListener('change', async function (event) {
            const file = event.target.files && event.target.files[0];
            if (!file) {
                return;
            }
            try {
                await processFile(file);
            } catch (err) {
                console.error('QR processing error', err);
                setStatus('We could not read that QR code. Please try again or enter the QR code short ID manually.');
            } finally {
                fileInput.value = '';
            }
        });

        async function processFile(file) {
            if (barcodeSupported) {
                await processWithBarcodeDetector(file);
                return;
            }
            if (jsQRSupported) {
                await processWithJsQR(file);
            }
        }

        async function processWithBarcodeDetector(file) {
            const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
            const bitmap = await createImageBitmap(file);
            try {
                const codes = await detector.detect(bitmap);
                if (!codes || codes.length === 0) {
                    setStatus('No QR code detected. Try taking the photo again.');
                    return;
                }
                for (const code of codes) {
                    if (navigateFromQR(code.rawValue)) {
                        return;
                    }
                }
                setStatus('This QR code does not point to a WireVault access link.');
            } finally {
                if (typeof bitmap.close === 'function') {
                    bitmap.close();
                }
            }
        }

        async function processWithJsQR(file) {
            try {
                const image = await loadImage(file);
                if (!image.naturalWidth || !image.naturalHeight) {
                    setStatus('No QR code detected. Try taking the photo again.');
                    return;
                }
                const canvas = document.createElement('canvas');
                canvas.width = image.naturalWidth;
                canvas.height = image.naturalHeight;
                const ctx = canvas.getContext('2d', { willReadFrequently: true });
                ctx.drawImage(image, 0, 0);
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const result = window.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'dontInvert' });
                if (result && navigateFromQR(result.data)) {
                    return;
                }
                setStatus('We could not read that QR code. Please try again or enter the QR code short ID manually.');
            } catch (err) {
                throw err;
            }
        }

        function loadImage(file) {
            return new Promise(function (resolve, reject) {
                const reader = new FileReader();
                reader.onload = function () {
                    const img = new Image();
                    img.onload = function () { resolve(img); };
                    img.onerror = function (event) { reject(event.error || new Error('Image load failed')); };
                    img.src = reader.result;
                };
                reader.onerror = function () { reject(reader.error || new Error('Image read failed')); };
                reader.readAsDataURL(file);
            });
        }

        function navigateFromQR(rawValue) {
            if (!rawValue) {
                return false;
            }
            let parsed;
            try {
                parsed = new URL(rawValue, window.location.origin);
            } catch (err) {
                return false;
            }
            if (!parsed.pathname.startsWith('/access/')) {
                return false;
            }
            const destination = parsed.pathname + parsed.search + parsed.hash;
            window.location.href = destination;
            return true;
        }

        function setStatus(message) {
            if (statusEl) {
                statusEl.textContent = message;
            }
        }

        function clearStatus() {
            setStatus('');
        }
    });
})();
