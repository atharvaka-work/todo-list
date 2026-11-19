import { useEffect, useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Checkbox from '@mui/material/Checkbox';
import Container from '@mui/material/Container';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import Typography from '@mui/material/Typography';
import DeleteOutlinedIcon from '@mui/icons-material/DeleteOutlined';
import dayjs from 'dayjs';
import { toast } from 'react-toastify';
import { v4 as uuidv4 } from 'uuid';
import Background from './Background';

const STORAGE_KEY = 'todo-list.items';

function readTasks() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export default function App() {
  const [tasks, setTasks] = useState(readTasks);
  const [draft, setDraft] = useState('');
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(tasks));
  }, [tasks]);

  const visibleTasks = useMemo(() => {
    if (filter === 'active') {
      return tasks.filter((task) => !task.completed);
    }
    if (filter === 'done') {
      return tasks.filter((task) => task.completed);
    }
    return tasks;
  }, [filter, tasks]);

  function addTask(event) {
    event.preventDefault();
    const title = draft.trim();
    if (!title) {
      return;
    }
    setTasks((current) => [
      {
        id: uuidv4(),
        title,
        completed: false,
        createdAt: new Date().toISOString(),
      },
      ...current,
    ]);
    setDraft('');
    toast.success('Task added');
  }

  function toggleTask(id) {
    setTasks((current) =>
      current.map((task) =>
        task.id === id ? { ...task, completed: !task.completed } : task,
      ),
    );
  }

  function deleteTask(id) {
    setTasks((current) => current.filter((task) => task.id !== id));
  }

  function changeFilter(_event, value) {
    if (value) {
      setFilter(value);
    }
  }

  const remaining = tasks.filter((task) => !task.completed).length;

  const surface = {
    backgroundColor: 'rgba(255, 255, 255, 0.9)',
    backdropFilter: 'blur(16px)',
  };

  return (
    <>
      <Background />
      <Container className="app-shell" maxWidth="sm" sx={{ py: 6 }}>
      <Stack spacing={3}>
        <Box>
          <Typography variant="h4" component="h1" sx={{ color: '#f8fafc' }}>
            To-do list
          </Typography>
          <Typography sx={{ color: 'rgba(248, 250, 252, 0.76)' }}>
            {remaining} active {remaining === 1 ? 'task' : 'tasks'}
          </Typography>
        </Box>

        <Paper component="form" onSubmit={addTask} sx={{ p: 2, ...surface }}>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
            <TextField
              label="New task"
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              fullWidth
              autoFocus
            />
            <Button type="submit" variant="contained" size="large">
              Add
            </Button>
          </Stack>
        </Paper>

        <ToggleButtonGroup
          exclusive
          value={filter}
          onChange={changeFilter}
          aria-label="Filter tasks"
          sx={{
            alignSelf: 'flex-start',
            backgroundColor: 'rgba(255, 255, 255, 0.14)',
            backdropFilter: 'blur(12px)',
            '& .MuiToggleButton-root': {
              color: '#e2e8f0',
              borderColor: 'rgba(255, 255, 255, 0.22)',
            },
            '& .Mui-selected': {
              color: '#082f49 !important',
              backgroundColor: 'rgba(224, 242, 254, 0.95) !important',
            },
          }}
        >
          <ToggleButton value="all">All</ToggleButton>
          <ToggleButton value="active">Active</ToggleButton>
          <ToggleButton value="done">Done</ToggleButton>
        </ToggleButtonGroup>

        <Paper sx={surface}>
          {visibleTasks.length === 0 ? (
            <Typography sx={{ p: 2 }} color="text.secondary">
              No tasks in this view.
            </Typography>
          ) : (
            <List>
              {visibleTasks.map((task) => (
                <ListItem
                  key={task.id}
                  secondaryAction={
                    <IconButton
                      edge="end"
                      aria-label={`Delete ${task.title}`}
                      onClick={() => deleteTask(task.id)}
                    >
                      <DeleteOutlinedIcon />
                    </IconButton>
                  }
                >
                  <ListItemIcon>
                    <Checkbox
                      edge="start"
                      checked={task.completed}
                      onChange={() => toggleTask(task.id)}
                      slotProps={{
                        input: { 'aria-label': `Mark ${task.title} complete` },
                      }}
                    />
                  </ListItemIcon>
                  <ListItemText
                    primary={task.title}
                    secondary={dayjs(task.createdAt).format('MMM D, YYYY h:mm A')}
                    sx={{
                      textDecoration: task.completed ? 'line-through' : 'none',
                    }}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Paper>
      </Stack>
      </Container>
    </>
  );
}
