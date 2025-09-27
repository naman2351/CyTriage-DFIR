'use client';

import { useState } from 'react';

interface FileUploadProps {
  onAnalysisComplete: (data: any) => void;
}

export default function FileUpload({ onAnalysisComplete }: FileUploadProps) {
  const [isUploading, setIsUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    setUploadMessage('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      
      if (result.success) {
        setUploadMessage(`File ${file.name} uploaded successfully!`);
        // Trigger analysis automatically
        await handleAnalysis(file.name);
      } else {
        setUploadMessage(`Upload failed: ${result.error}`);
      }
    } catch (error) {
      setUploadMessage('Upload failed. Please try again.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleAnalysis = async (filename: string) => {
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ filename }),
      });

      const result = await response.json();
      
      if (result.success) {
        onAnalysisComplete(result);
      } else {
        setUploadMessage('Analysis failed. Please try again.');
      }
    } catch (error) {
      console.error('Analysis error:', error);
      setUploadMessage('Analysis failed. Please try again.');
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">Upload Forensic Image</h2>
      <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
        <input 
          type="file" 
          onChange={handleFileUpload}
          disabled={isUploading}
          accept=".raw,.img,.bin,.mem"
          className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
        />
        <p className="mt-2 text-sm text-gray-600">Supported formats: RAW, IMG, BIN, MEM</p>
        {isUploading && (
          <div className="mt-4">
            <div className="animate-pulse flex space-x-4">
              <div className="flex-1 space-y-4 py-1">
                <div className="h-2 bg-blue-200 rounded"></div>
                <div className="h-2 bg-blue-200 rounded"></div>
              </div>
            </div>
            <p className="text-sm text-blue-600 mt-2">Uploading and analyzing...</p>
          </div>
        )}
        {uploadMessage && (
          <p className={`mt-4 text-sm ${
            uploadMessage.includes('failed') ? 'text-red-600' : 'text-green-600'
          }`}>
            {uploadMessage}
          </p>
        )}
      </div>
    </div>
  );
}