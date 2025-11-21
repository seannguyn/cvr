import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
});

export const uploadReport = async (file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post('/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

export const generateReport = async (date: string) => {
  return api.post('/cvr', { date });
};

export const getReport = async (date: string) => {
  return api.get(`/reports/${date}`, { responseType: 'blob' });
};
