import React, { useState, useEffect, useMemo } from 'react';
import { Container, Typography, Box, Paper, Alert, CircularProgress, Chip, Stack } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { Dayjs } from 'dayjs';
import { uploadReport, generateReport, getReport, getAvailableDates } from './api';
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
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import UnfoldMoreIcon from '@mui/icons-material/UnfoldMore';

// Define the shape of our data
interface ReportRow {
  Image: string;
  AssetName: string;
  Severity: string;
  CVEs: string;
  'Scan Date': string;
  Namespace: string;
  ParentKind: string;
  ParentName: string;
}

// Helper to parse markdown links [Name](Link)
const CVERenderer = ({ value }: { value: string }) => {
  if (!value) return null;
  // Split by comma, but be careful if comma is inside [] or ().
  // Simple split by ", " should work for our generated data.
  const cves = value.split(', ');
  return (
    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
      {cves.map((cve, index) => {
        const match = cve.match(/\[(.*?)\]\((.*?)\)/);
        if (match) {
          return (
            <span key={index}>
              <a
                href={match[2]}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: '#1976d2', textDecoration: 'none', fontWeight: 500 }}
                onClick={(e) => e.stopPropagation()} // Prevent row click if any
              >
                {match[1]}
              </a>
              {index < cves.length - 1 && ', '}
            </span>
          );
        }
        return <span key={index}>{cve}{index < cves.length - 1 && ', '}</span>;
      })}
    </Box>
  );
};

// Severity Chip Renderer
const SeverityRenderer = ({ value }: { value: string }) => {
  if (!value) return null;

  let bgcolor = '#e0e0e0';
  let textcolor = '#000';

  switch (value) {
    case 'Critical':
      bgcolor = '#ffebee'; // Light red
      textcolor = '#d32f2f';
      break;
    case 'High':
      bgcolor = '#fff3e0'; // Light orange
      textcolor = '#ed6c02';
      break;
    case 'Medium':
      bgcolor = '#ffe9aeff'; // Light yellow
      textcolor = '#827704ff'; // Yellow
      break;
    case 'Low':
      bgcolor = '#f5f5f5'; // Light gray
      textcolor = '#616161';
      break;
  }

  // If using standard chips, we can use color prop. But for specific "light background same color", custom sx is better.
  return (
    <Chip
      label={value}
      size="small"
      sx={{
        bgcolor: bgcolor,
        color: textcolor,
        fontWeight: 'bold'
      }}
    />
  );
};

// Highlight Renderer
const HighlightCell = ({ value, filter }: { value: string, filter: string }) => {
  if (!value) return null;
  if (!filter) return <span>{value}</span>;

  const parts = value.split(new RegExp(`(${filter})`, 'gi'));
  return (
    <span>
      {parts.map((part, i) =>
        part.toLowerCase() === filter.toLowerCase() ? (
          <span key={i} style={{ backgroundColor: '#ffeb3b' }}>{part}</span>
        ) : (
          part
        )
      )}
    </span>
  );
};


function App() {
  const [selectedDate, setSelectedDate] = useState<Dayjs | null>(null);
  const [availableDates, setAvailableDates] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [data, setData] = useState<ReportRow[]>([]);
  const [globalFilter, setGlobalFilter] = useState('');

  // Environment variable for Cluster Name (Vite uses import.meta.env)
  const clusterName = import.meta.env.VITE_CLUSTER_NAME || 'UNKNOWN_CLUSTER';

  useEffect(() => {
    const fetchDates = async () => {
      try {
        const res = await getAvailableDates();
        setAvailableDates(res.data.dates);
      } catch (e) {
        console.error("Failed to fetch dates", e);
      }
    };
    fetchDates();
  }, []);

  const handleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      try {
        setLoading(true);
        await uploadReport(event.target.files[0]);
        setMessage({ type: 'success', text: 'Wiz report uploaded successfully!' });
        // Refresh dates
        const res = await getAvailableDates();
        setAvailableDates(res.data.dates);
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
        skipEmptyLines: true, // Important to avoid empty rows
        complete: (results) => {
          setData(results.data);
          setMessage({ type: 'success', text: `Abracadabra! Report generated successfully for date: ${dateStr}!` });
        },
      });
    } catch (error) {
      setMessage({ type: 'error', text: 'Looks like our bot is on sick leave today. Please try again, or contact PCCS.' });
    } finally {
      setLoading(false);
    }
  };

  const columnHelper = createColumnHelper<ReportRow>();

  const columns = useMemo(() => [
    columnHelper.accessor('Image', {
      header: 'Image',
      cell: info => <HighlightCell value={info.getValue()} filter={globalFilter} />
    }),
    columnHelper.accessor('AssetName', {
      header: 'Asset Name',
      cell: info => <HighlightCell value={info.getValue()} filter={globalFilter} />
    }),
    columnHelper.accessor('Severity', {
      header: 'Severity',
      cell: info => <SeverityRenderer value={info.getValue()} />
    }),
    columnHelper.accessor('CVEs', {
      header: 'CVEs',
      cell: info => <CVERenderer value={info.getValue()} />
    }),
    columnHelper.accessor('Scan Date', { header: 'Scan Date' }),
    columnHelper.accessor('Namespace', {
      header: 'Namespace',
      cell: info => <HighlightCell value={info.getValue()} filter={globalFilter} />
    }),
    columnHelper.accessor('ParentKind', { header: 'Kind' }),
    columnHelper.accessor('ParentName', {
      header: 'Name',
      cell: info => <HighlightCell value={info.getValue()} filter={globalFilter} />
    }),
  ], [globalFilter]);

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

  // Calculate counts
  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    data.forEach(row => {
      if (row.Severity in c) {
        c[row.Severity as keyof typeof c]++;
      }
    });
    return c;
  }, [data]);

  const isDateDisabled = (date: Dayjs) => {
    return !availableDates.includes(date.format('YYYY-MM-DD'));
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDayjs}>
      <Container maxWidth="xl" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          Container Vulnerability Report: {clusterName}
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
              shouldDisableDate={isDateDisabled}
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
            <Box sx={{ mb: 2 }}>
              <Typography variant="h6">
                Container Vulnerabilities Report <b>{selectedDate?.format('YYYY-MM-DD')}</b>
              </Typography>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography variant="subtitle1">with:</Typography>
                <Typography>{counts.Critical}</Typography><SeverityRenderer value="Critical" />
                <Typography>{counts.High}</Typography><SeverityRenderer value="High" />
                <Typography>{counts.Medium}</Typography><SeverityRenderer value="Medium" />
                <Typography>{counts.Low}</Typography><SeverityRenderer value="Low" />
              </Stack>
            </Box>

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
                            whiteSpace: 'nowrap',
                          }}
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {{
                              asc: <ArrowUpwardIcon fontSize="small" />,
                              desc: <ArrowDownwardIcon fontSize="small" />,
                            }[header.column.getIsSorted() as string] ?? <UnfoldMoreIcon fontSize="small" color="action" />}
                          </Box>
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

            <Box sx={{ mt: 2, display: 'flex', gap: 2, justifyContent: 'center', alignItems: 'center' }}>
              <Button
                variant="outlined"
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
              >
                Previous
              </Button>
              <Typography sx={{ alignSelf: 'center' }}>
                Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
              </Typography>
              <Button
                variant="outlined"
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
              >
                Next
              </Button>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography>Show:</Typography>
                <select
                  value={table.getState().pagination.pageSize}
                  onChange={e => {
                    table.setPageSize(Number(e.target.value))
                  }}
                  style={{ padding: '5px', borderRadius: '4px' }}
                >
                  {[10, 20, 50, 100].map(pageSize => (
                    <option key={pageSize} value={pageSize}>
                      {pageSize}
                    </option>
                  ))}
                </select>
              </Box>
            </Box>
          </Paper>
        )}
      </Container>
    </LocalizationProvider>
  );
}

export default App;
