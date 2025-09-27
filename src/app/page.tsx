'use client';

import { useState } from 'react';
import FileUpload from './components/FileUpload';
import AnalysisResults from './components/AnalysisResults';

export default function Home() {
  const [analysisData, setAnalysisData] = useState<any>(null);

  const handleAnalysisComplete = (data: any) => {
    setAnalysisData(data);
  };

  return (
    <div className="min-h-screen bg-gray-100 py-8">
      <div className="container mx-auto px-4 max-w-6xl">
        {/* Header */}
        <header className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-800 mb-2">CyTriage</h1>
          <p className="text-gray-600">Digital Forensics & Incident Response Tool</p>
        </header>

        {/* Main Content */}
        <main className="space-y-8">
          <FileUpload onAnalysisComplete={handleAnalysisComplete} />
          {analysisData && <AnalysisResults data={analysisData} />}
        </main>

        {/* Footer */}
        <footer className="mt-12 text-center text-gray-500 text-sm">
          <p>CyTriage MVP - Built for DFIR analysis</p>
        </footer>
      </div>
    </div>
  );
}