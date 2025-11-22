import React, { useState, useEffect, useMemo } from 'react';
import { Container, Typography, Box, Paper, Alert, Chip, Stack, Link, Menu, MenuItem, Checkbox, FormControlLabel, Divider, Tooltip } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import dayjs, { Dayjs } from 'dayjs';
import { uploadReport, generateReport, getReport, getAvailableDates, downloadReport } from './api';
import Papa from 'papaparse';
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
  VisibilityState,
} from '@tanstack/react-table';
import { Button, TextField, TablePagination } from '@mui/material';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import UnfoldMoreIcon from '@mui/icons-material/UnfoldMore';
import ViewColumnIcon from '@mui/icons-material/ViewColumn';
import DownloadIcon from '@mui/icons-material/Download';

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
  CMDB: string;
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

const SEVERITY_COLORS = {
  Critical: { bg: '#ffebee', text: '#d32f2f' },
  High: { bg: '#fff3e0', text: '#ed6c02' },
  Medium: { bg: '#ffe9aeff', text: '#a59700ff' },
  Low: { bg: '#f5f5f5', text: '#616161' },
};

// Severity Chip Renderer
const SeverityRenderer = ({ value }: { value: string }) => {
  if (!value) return null;

  const colors = SEVERITY_COLORS[value as keyof typeof SEVERITY_COLORS] || { bg: '#e0e0e0', text: '#000' };

  return (
    <Chip
      label={value}
      size="small"
      sx={{
        bgcolor: colors.bg,
        color: colors.text,
        fontWeight: 'bold'
      }}
    />
  );
};

// Highlight Renderer
const HighlightCell = ({ value, filter, globalFilter }: { value: string, filter?: string, globalFilter?: string }) => {
  if (!value) return null;

  const filters = [filter, globalFilter].filter(f => f && f.trim() !== '');

  if (filters.length === 0) return <span>{value}</span>;

  // Escape special regex characters in filters to avoid crashes
  const escapedFilters = filters.map(f => f?.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const pattern = `(${escapedFilters.join('|')})`;

  const parts = value.split(new RegExp(pattern, 'gi'));
  return (
    <span>
      {parts.map((part, i) => {
        const isMatch = filters.some(f => part.toLowerCase() === f?.toLowerCase());
        return isMatch ? (
          <span key={i} style={{ backgroundColor: '#ffeb3b' }}>{part}</span>
        ) : (
          part
        );
      })}
    </span>
  );
};

// CMDB Renderer
const CMDBRenderer = ({ value, filter, globalFilter }: { value: string, filter?: string, globalFilter?: string }) => {
  if (!value) return null;
  const items = value.split(',');
  return (
    <Box>
      {items.map((item, i) => (
        <div key={i}>
          <HighlightCell value={item} filter={filter} globalFilter={globalFilter} />
        </div>
      ))}
    </Box>
  );
};

// Column Filter Component
const Filter = ({ column }: { column: any, table: any }) => {
  const columnFilterValue = column.getFilterValue();

  return (
    <TextField
      variant="standard"
      size="small"
      value={(columnFilterValue ?? '') as string}
      onChange={e => column.setFilterValue(e.target.value)}
      placeholder={`Filter...`}
      onClick={e => e.stopPropagation()}
      sx={{ mt: 1, width: '100%' }}
    />
  );
};


function App() {
  const [selectedDate, setSelectedDate] = useState<Dayjs | null>(null);
  const [availableDates, setAvailableDates] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string | React.ReactNode } | null>(null);
  const [data, setData] = useState<ReportRow[]>([]);
  const [globalFilter, setGlobalFilter] = useState('');

  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({
    'Scan Date': false, // Hide Scan Date by default
  });

  // Column Visibility Menu State
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  // Environment variable for Cluster Name (Runtime config or Vite build time fallback)
  const clusterName = window.config?.clusterName || import.meta.env.VITE_CLUSTER_NAME || 'UNKNOWN_CLUSTER';

  useEffect(() => {
    const fetchDates = async () => {
      try {
        const res = await getAvailableDates();
        const dates = res.data.dates;
        setAvailableDates(dates);

        // Auto-select today if available
        const today = dayjs().format('YYYY-MM-DD');
        if (dates.includes(today)) {
          setSelectedDate(dayjs(today));
        }
      } catch (e) {
        console.error("Failed to fetch dates", e);
      }
    };
    fetchDates();
  }, []);

  // Effect to generate/fetch report when date is selected
  useEffect(() => {
    const fetchReport = async () => {
      if (!selectedDate) {
        setData([]);
        return;
      }

      const dateStr = selectedDate.format('YYYY-MM-DD');
      try {
        setLoading(true);
        setMessage(null);

        // Check if we need to generate it first (if it's today and not generated yet?
        // The requirement says "if there is report for today, date picker auto pick today's date, and display TanStack CVE table"
        // But if we just uploaded, we might need to generate.
        // Let's try to generate, backend handles "if exists return it".
        await generateReport(dateStr);

        // Fetch the generated report
        const response = await getReport(dateStr);
        const text = await response.data.text();

        Papa.parse<ReportRow>(text, {
          header: true,
          skipEmptyLines: true, // Important to avoid empty rows
          transformHeader: (header) => header.trim(), // Handle potential CRLF issues
          complete: (results) => {
            setData(results.data);
            setMessage({ type: 'success', text: <span>Abracadabra! Report generated successfully for date: <strong>{dateStr}</strong>!</span> });
          },
        });
      } catch (error) {
        setMessage({ type: 'error', text: 'Looks like our bot is on sick leave today. Please try again, or contact PCCS.' });
        setData([]);
      } finally {
        setLoading(false);
      }
    };

    fetchReport();
  }, [selectedDate]);

  const handleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      try {
        setLoading(true);
        await uploadReport(event.target.files[0]);
        setMessage({ type: 'success', text: 'Wiz report uploaded successfully!' });

        const today = dayjs().format('YYYY-MM-DD');
        setAvailableDates(prev => [...prev, today]);
        setSelectedDate(dayjs(today));

      } catch (error) {
        setMessage({ type: 'error', text: 'Failed to upload report.' });
      } finally {
        setLoading(false);
      }
    }
  };

  const handleDownload = async () => {
    if (!selectedDate) return;
    const dateStr = selectedDate.format('YYYY-MM-DD');
    try {
      const response = await downloadReport(dateStr);
      // Create blob link to download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;

      const contentDisposition = response.headers['content-disposition'];
      let filename = `${clusterName}-cvr-${dateStr}.zip`;
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
        if (filenameMatch && filenameMatch.length === 2)
          filename = filenameMatch[1];
      }

      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (e) {
      console.error("Download failed", e);
      setMessage({ type: 'error', text: "Failed to download report." });
    }
  };

  const columnHelper = createColumnHelper<ReportRow>();

  const columns = useMemo(() => [
    columnHelper.accessor('Image', {
      header: 'Image',
      cell: info => <HighlightCell value={info.getValue()} filter={info.column.getFilterValue() as string} globalFilter={globalFilter} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('AssetName', {
      header: 'Asset Name',
      cell: info => <HighlightCell value={info.getValue()} filter={info.column.getFilterValue() as string} globalFilter={globalFilter} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('Severity', {
      header: 'Severity',
      cell: info => <SeverityRenderer value={info.getValue()} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('CVEs', {
      header: 'CVEs',
      cell: info => <CVERenderer value={info.getValue()} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('Scan Date', {
      header: 'Scan Date',
      enableColumnFilter: true,
    }),
    columnHelper.accessor('CMDB', {
      header: 'CMDB',
      cell: info => <CMDBRenderer value={info.getValue()} filter={info.column.getFilterValue() as string} globalFilter={globalFilter} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('Namespace', {
      header: 'Namespace',
      cell: info => <HighlightCell value={info.getValue()} filter={info.column.getFilterValue() as string} globalFilter={globalFilter} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('ParentKind', {
      header: 'Kind',
      cell: info => <HighlightCell value={info.getValue()} filter={info.column.getFilterValue() as string} globalFilter={globalFilter} />,
      enableColumnFilter: true,
    }),
    columnHelper.accessor('ParentName', {
      header: 'Name',
      cell: info => <HighlightCell value={info.getValue()} filter={info.column.getFilterValue() as string} globalFilter={globalFilter} />,
      enableColumnFilter: true,
    }),
  ], [globalFilter]);

  const table = useReactTable({
    data,
    columns,
    state: {
      globalFilter,
      columnVisibility,
    },
    initialState: {
      pagination: {
        pageSize: 100,
      }
    },
    onGlobalFilterChange: setGlobalFilter,
    onColumnVisibilityChange: setColumnVisibility,
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
        // Count number of CVEs in this row (split by comma)
        const cveCount = row.CVEs ? row.CVEs.split(', ').length : 0;
        c[row.Severity as keyof typeof c] += cveCount;
      }
    });
    return c;
  }, [data]);

  const isDateDisabled = (date: Dayjs) => {
    return !availableDates.includes(date.format('YYYY-MM-DD'));
  };

  return (
    <LocalizationProvider dateAdapter={AdapterDayjs}>
      <Container maxWidth={false} sx={{ mt: 4, px: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <img src="/logo.png" alt="Logo" style={{ height: '50px' }} />
          Container Vulnerability Report (CVR): {clusterName}
        </Typography>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
            <Button variant="contained" component="label">
              Upload Today's Wiz Report
              <input hidden accept=".csv" type="file" onChange={handleUpload} />
            </Button>

            <Tooltip title={<div style={{ whiteSpace: 'pre-line' }}>Container Vulnerability Report{'\n'}is only available for current month</div>} arrow>
              <div>
                <DatePicker
                  label="Select Date"
                  value={selectedDate}
                  onChange={(newValue) => setSelectedDate(newValue)}
                  shouldDisableDate={isDateDisabled}
                  minDate={dayjs().startOf('month')}
                  maxDate={dayjs().endOf('month')}
                />
              </div>
            </Tooltip>
            {/* Generate button removed as per requirement */}
          </Box>

          {message && (
            <Alert severity={message.type} sx={{ mt: 2 }}>
              {message.text}
            </Alert>
          )}
        </Paper>

        {data.length === 0 && !loading && (
          <Paper sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="h6" gutterBottom>
              Upload Today's wiz report to view today's live CVEs.
            </Typography>
            <Typography variant="body1" gutterBottom>
              Instructions to export Wiz Container Vulnerabilities report is <Link href="https://app.wiz.io" target="_blank" rel="noopener">here</Link>.
            </Typography>
            <Typography variant="body2" color="textSecondary">
              View previous reports by select date in the past.
            </Typography>
          </Paper>
        )}

        {data.length > 0 && (
          <Paper sx={{ p: 3 }}>
            <Box sx={{ mb: 2 }}>
              <Typography variant="h6">
                Container Vulnerabilities Report <b>{selectedDate?.format('YYYY-MM-DD')}</b>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleDownload}
                  sx={{ ml: 2 }}
                  disabled={!selectedDate || data.length === 0}
                >
                  Download
                </Button>
              </Typography>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography sx={{ color: SEVERITY_COLORS.Critical.text, fontWeight: 'bold' }}>{counts.Critical}</Typography><SeverityRenderer value="Critical" />
                <Typography sx={{ color: SEVERITY_COLORS.High.text, fontWeight: 'bold' }}>{counts.High}</Typography><SeverityRenderer value="High" />
                <Typography sx={{ color: SEVERITY_COLORS.Medium.text, fontWeight: 'bold' }}>{counts.Medium}</Typography><SeverityRenderer value="Medium" />
                <Typography sx={{ color: SEVERITY_COLORS.Low.text, fontWeight: 'bold' }}>{counts.Low}</Typography><SeverityRenderer value="Low" />
              </Stack>
            </Box>

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <TextField
                value={globalFilter ?? ''}
                onChange={(e) => setGlobalFilter(e.target.value)}
                placeholder="Search all columns..."
                variant="outlined"
                size="small"
                sx={{ width: '600px' }}
              />

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Button
                  onClick={handleClick}
                  startIcon={<ViewColumnIcon />}
                  variant="outlined"
                  size="medium"
                >
                  Columns
                </Button>
                <Menu
                  id="column-menu"
                  anchorEl={anchorEl}
                  open={open}
                  onClose={handleClose}
                  MenuListProps={{
                    'aria-labelledby': 'basic-button',
                  }}
                >
                  {table.getAllLeafColumns().map(column => {
                    return (
                      <MenuItem key={column.id} dense>
                        <FormControlLabel
                          control={
                            <Checkbox
                              checked={column.getIsVisible()}
                              onChange={column.getToggleVisibilityHandler()}
                            />
                          }
                          label={column.columnDef.header as string}
                        />
                      </MenuItem>
                    )
                  })}
                  <Divider />
                  <MenuItem dense>
                    <FormControlLabel
                      control={
                        <Checkbox
                          checked={table.getIsAllColumnsVisible()}
                          indeterminate={table.getIsSomeColumnsVisible() && !table.getIsAllColumnsVisible()}
                          onChange={table.getToggleAllColumnsVisibilityHandler()}
                        />
                      }
                      label="Show/Hide All"
                    />
                  </MenuItem>
                </Menu>

                <TablePagination
                  component="div"
                  count={table.getFilteredRowModel().rows.length}
                  page={table.getState().pagination.pageIndex}
                  onPageChange={(_, newPage) => table.setPageIndex(newPage)}
                  rowsPerPage={table.getState().pagination.pageSize}
                  onRowsPerPageChange={(e) => table.setPageSize(Number(e.target.value))}
                  rowsPerPageOptions={[10, 20, 50, 100]}
                  showFirstButton
                  showLastButton
                  sx={{ border: 'none' }}
                />
              </Box>
            </Box>

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
                            verticalAlign: 'top',
                          }}
                        >
                          <Box
                            onClick={header.column.getToggleSortingHandler()}
                            sx={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 0.5,
                              cursor: 'pointer',
                              whiteSpace: 'nowrap'
                            }}
                          >
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {{
                              asc: <ArrowUpwardIcon fontSize="small" />,
                              desc: <ArrowDownwardIcon fontSize="small" />,
                            }[header.column.getIsSorted() as string] ?? <UnfoldMoreIcon fontSize="small" color="action" />}
                          </Box>
                          {header.column.getCanFilter() ? (
                            <Filter column={header.column} table={table} />
                          ) : null}
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

            <TablePagination
              component="div"
              count={table.getFilteredRowModel().rows.length}
              page={table.getState().pagination.pageIndex}
              onPageChange={(_, newPage) => table.setPageIndex(newPage)}
              rowsPerPage={table.getState().pagination.pageSize}
              onRowsPerPageChange={(e) => table.setPageSize(Number(e.target.value))}
              rowsPerPageOptions={[10, 20, 50, 100]}
              showFirstButton
              showLastButton
            />
          </Paper>
        )}
      </Container>
    </LocalizationProvider>
  );
}

export default App;
