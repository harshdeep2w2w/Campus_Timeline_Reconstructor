/**
 * Campus Network Attack – Timeline Reconstructor
 * Upload & Ingestion Logic (upload.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('fileInput');
    const browseBtn = document.getElementById('browseFilesBtn');
    const uploadForm = document.getElementById('uploadForm');
    const datasetNameInput = document.getElementById('datasetNameInput');
    const fileInfoBox = document.getElementById('selectedFileInfo');
    const fileNameEl = document.getElementById('selectedFileName');
    const fileSizeEl = document.getElementById('selectedFileSize');
    const clearFileBtn = document.getElementById('clearFileBtn');
    const progressContainer = document.getElementById('uploadProgressContainer');
    const progressBar = document.getElementById('uploadProgressBar');
    const percentLabel = document.getElementById('uploadPercentLabel');
    const submitBtn = document.getElementById('submitUploadBtn');
    const resultsCard = document.getElementById('uploadResultsCard');
    const sampleBtn = document.getElementById('uploadLoadSampleBtn');

    // Sample dataset button handler
    if (sampleBtn) {
        sampleBtn.addEventListener('click', async () => {
            await CTR.loadSampleData();
        });
    }

    // Format bytes into human readable format
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Update UI when file is chosen
    function handleFileSelected(file) {
        if (!file) return;

        // Check extension
        const validExtensions = ['.csv', '.json', '.log', '.txt'];
        const fileName = file.name.toLowerCase();
        const isValid = validExtensions.some(ext => fileName.endsWith(ext));

        if (!isValid) {
            CTR.showToast('Please select a supported log format (.csv, .json, .log, .txt)', 'error', 'Invalid Format');
            clearSelectedFile();
            return;
        }

        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = formatBytes(file.size);
        fileInfoBox.style.display = 'block';

        // Auto-fill dataset name if user hasn't typed one yet
        if (!datasetNameInput.value.trim()) {
            const baseName = file.name.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_-]/g, '-');
            datasetNameInput.value = `${baseName}-${new Date().toISOString().slice(0, 10)}`;
        }
    }

    function clearSelectedFile() {
        fileInput.value = '';
        fileInfoBox.style.display = 'none';
        fileNameEl.textContent = '';
        fileSizeEl.textContent = '';
    }

    // Browse Button
    if (browseBtn && fileInput) {
        browseBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => {
            fileInput.click();
        });

        // Drag & Drop Listeners
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('drag-active');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('drag-active');
            }, false);
        });

        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                handleFileSelected(files[0]);
            }
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files.length > 0) {
                handleFileSelected(fileInput.files[0]);
            }
        });
    }

    if (clearFileBtn) {
        clearFileBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            clearSelectedFile();
        });
    }

    // Form Submission
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            if (!fileInput.files || fileInput.files.length === 0) {
                CTR.showToast('Please select a log telemetry file to upload', 'warning', 'Missing File');
                return;
            }

            const datasetName = datasetNameInput.value.trim();
            if (!datasetName) {
                CTR.showToast('Please specify a dataset name', 'warning', 'Missing Name');
                datasetNameInput.focus();
                return;
            }

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            formData.append('dataset_name', datasetName);

            // Display loading progress
            progressContainer.style.display = 'block';
            progressBar.style.width = '35%';
            percentLabel.textContent = '35%';
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Ingesting &amp; Parsing...';

            try {
                // Simulate progress jump for visual feedback
                const progressInterval = setInterval(() => {
                    let current = parseInt(progressBar.style.width, 10);
                    if (current < 85) {
                        current += 10;
                        progressBar.style.width = current + '%';
                        percentLabel.textContent = current + '%';
                    }
                }, 300);

                const response = await CTR.apiCall('/api/upload', {
                    method: 'POST',
                    body: formData
                });

                clearInterval(progressInterval);
                progressBar.style.width = '100%';
                percentLabel.textContent = '100%';

                CTR.showToast(`Ingested ${response.record_count || 0} events successfully!`, 'success', 'Ingestion Complete');

                // Render Results Card
                if (resultsCard) {
                    document.getElementById('resultRecordCount').textContent = (response.record_count || 0).toLocaleString();
                    document.getElementById('resultErrorCount').textContent = (response.errors ? (Array.isArray(response.errors) ? response.errors.length : response.errors) : 0);
                    document.getElementById('resultDatasetId').textContent = '#' + (response.dataset_id || '--');

                    // Render Preview Table
                    const tbody = document.getElementById('resultPreviewTableBody');
                    if (tbody && Array.isArray(response.preview) && response.preview.length > 0) {
                        tbody.innerHTML = response.preview.slice(0, 5).map(record => `
                            <tr>
                                <td class="font-monospace fs-xs">${CTR.formatTimestamp(record.timestamp)}</td>
                                <td class="font-monospace">${record.src_ip || 'N/A'}${record.src_port ? ':' + record.src_port : ''}</td>
                                <td class="font-monospace">${record.dst_ip || 'N/A'}${record.dst_port ? ':' + record.dst_port : ''}</td>
                                <td><span class="badge-protocol">${(record.protocol || 'TCP').toUpperCase()}</span></td>
                                <td><span class="badge bg-secondary">${record.event_category || 'traffic'}</span></td>
                                <td>${CTR.severityBadge(record.severity)}</td>
                            </tr>
                        `).join('');
                    } else if (tbody) {
                        tbody.innerHTML = '<tr><td colspan="6" class="text-center py-3 text-secondary">Parsed telemetry records loaded into dataset repository.</td></tr>';
                    }

                    resultsCard.style.display = 'block';
                    resultsCard.scrollIntoView({ behavior: 'smooth' });
                }

                // Set new dataset as active across application
                if (response.dataset_id) {
                    CTR.setCurrentDatasetId(response.dataset_id, true);
                }
                await CTR.loadDatasets();

            } catch (error) {
                console.error('Upload failed:', error);
                CTR.showToast('Upload failed: ' + (error.message || 'Unknown network error'), 'error', 'Ingestion Failed');
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-cpu me-2"></i>Upload &amp; Analyze';
                setTimeout(() => {
                    progressContainer.style.display = 'none';
                    progressBar.style.width = '0%';
                }, 2000);
            }
        });
    }
});
