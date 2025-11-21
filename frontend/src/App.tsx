import React, { useState } from 'react';
import { Container, Typography, Box, Paper, Alert, CircularProgress } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import dayjs, { Dayjs } from 'dayjs';
import { uploadReport, generateReport, getReport } from './api';
import Papa from 'papaparse';
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
} from '@tanstack/react-table';
import { Button, TextField } from '@mui/material';

// Define the shape of our data
interface ReportRow {
  Cluster: string;
  Image: string;
  AssetName: string;
  Severity: string;
  CVEs: string;
  'Scan Date': string;
  Namespace: string;
  ParentKind: string;
  ParentName: string;
}

const columnHelper = createColumnHelper<ReportRow>();

const columns = [
  columnHelper.accessor('Cluster', { header: 'Cluster' }),
  columnHelper.accessor('Image', { header: 'Image' }),
  columnHelper.accessor('AssetName', { header: 'Asset Name' }),
  columnHelper.accessor('Severity', { header: 'Severity' }),
  columnHelper.accessor('CVEs', { header: 'CVEs' }),
  columnHelper.accessor('Scan Date', { header: 'Scan Date' }),
  columnHelper.accessor('Namespace', { header: 'Namespace' }),
  columnHelper.accessor('ParentKind', { header: 'Kind' }),
  columnHelper.accessor('ParentName', { header: 'Name' }),
];

function App() {
  const [selectedDate, setSelectedDate] = useState<Dayjs | null>(dayjs());
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [data, setData] = useState<ReportRow[]>([]);
  const [globalFilter, setGlobalFilter] = useState('');

  const handleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      try {
        setLoading(true);
        await uploadReport(event.target.files[0]);
        setMessage({ type: 'success', text: 'Wiz report uploaded successfully!' });
      } catch (error) {
        setMessage({ type: 'error', text: 'Failed to upload report.' });
      } finally {
        setLoading(false);
      }
    }
  };

  const handleGenerate = async () => {
    if (!selectedDate) return;
    const dateStr = selectedDate.format('YYYY-MM-DD');
    try {
      setLoading(true);
      setMessage(null);
      await generateReport(dateStr);

      // Fetch the generated report
      const response = await getReport(dateStr);
      const text = await response.data.text();

      Papa.parse<ReportRow>(text, {
        header: true,
        complete: (results) => {
          setData(results.data);
          setMessage({ type: 'success', text: 'Abracadabra! Report generated successfully!' });
        },
      });
    } catch (error) {
      setMessage({ type: 'error', text: 'Looks like our bot is on sick leave today. Please try again, or contact PCCS.' });
    } finally {
      setLoading(false);
    }
  };

  const table = useReactTable({
    data,
    columns,
    state: {
      globalFilter,
    },
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <LocalizationProvider dateAdapter={AdapterDayjs}>
      <Container maxWidth="xl" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          Container Vulnerability Report
        </Typography>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <Button variant="contained" component="label">
              Upload Wiz Report
              <input hidden accept=".csv" type="file" onChange={handleUpload} />
            </Button>

            <DatePicker
              label="Select Date"
              value={selectedDate}
              onChange={(newValue) => setSelectedDate(newValue)}
            />

            <Button
              variant="contained"
              color="secondary"
              onClick={handleGenerate}
              disabled={loading || !selectedDate}
            >
              {loading ? <CircularProgress size={24} /> : 'Generate Report'}
            </Button>
          </Box>

          {message && (
            <Alert severity={message.type} sx={{ mt: 2 }}>
              {message.text}
            </Alert>
          )}
        </Paper>

        {data.length > 0 && (
          <Paper sx={{ p: 3 }}>
            <TextField
              value={globalFilter ?? ''}
              onChange={(e) => setGlobalFilter(e.target.value)}
              placeholder="Search all columns..."
              variant="outlined"
              fullWidth
              sx={{ mb: 2 }}
            />

            <Box sx={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  {table.getHeaderGroups().map((headerGroup) => (
                    <tr key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <th
                          key={header.id}
                          style={{
                            padding: '10px',
                            borderBottom: '1px solid #ddd',
                            textAlign: 'left',
                            cursor: 'pointer',
                          }}
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {{
                            asc: ' 🔼',
                            desc: ' 🔽',
                          }[header.column.getIsSorted() as string] ?? null}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {table.getRowModel().rows.map((row) => (
                    <tr key={row.id}>
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id} style={{ padding: '10px', borderBottom: '1px solid #ddd' }}>
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>

            <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
              <Button
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
              >
                Previous
              </Button>
              <Button
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
              >
                Next
              </Button>
            </Box>
          </Paper>
        )}
      </Container>
    </LocalizationProvider>
  );
}

export default App;
