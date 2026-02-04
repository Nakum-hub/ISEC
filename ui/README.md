# ISEC Desktop UI

Modern cybersecurity evidence collection application with dark mode glassmorphism design.

## Features

- **Dark Mode Interface**: Professional dark theme optimized for security professionals
- **Glassmorphism Panels**: Frosted glass effect panels for modern aesthetics
- **Animated Timeline**: Smooth timeline visualization of collected evidence
- **Interactive Dashboard**: Real-time statistics and evidence status
- **Detailed Views**: Comprehensive evidence analysis and metadata
- **Report Generation**: Professional PDF and export capabilities

## Design Elements

### Color Palette
- Primary: `#007acc` (Professional blue)
- Secondary: `#00d4ff` (Cyber accent)
- Success: `#00cc66` (Verification green)
- Warning: `#ffaa00` (Alert amber)
- Danger: `#ff4444` (Critical red)
- Dark Background: `#0a0a0f`
- Glass Background: `rgba(30, 30, 46, 0.3)`

### Animation Effects
- Fade transitions between views
- Slide-in effects for timeline items
- Hover animations on interactive elements
- Loading spinners and overlays

### Component Hierarchy

```
ISEC Desktop App
├── Window Controls
├── Sidebar Navigation
│   ├── Dashboard
│   ├── Evidence Timeline
│   ├── Evidence Detail View
│   └── Report Export
└── Main Content Areas
    ├── Dashboard View
    │   ├── Stats Grid
    │   ├── Quick Actions
    │   └── Evidence Collection Controls
    ├── Timeline View
    │   ├── Filter Controls
    │   ├── Animated Timeline
    │   └── Evidence Cards
    ├── Detail View
    │   ├── Tabbed Interface
    │   ├── Evidence Metadata
    │   └── Chain of Custody
    └── Report Export View
        ├── Export Options
        ├── Format Selection
        └── Preview Panel
```

## Screens

### Dashboard Screen
- Evidence count statistics
- Integrity status indicators
- Quick collection buttons
- Recent activity feed

### Evidence Timeline Screen
- Chronological view of collected evidence
- Animated timeline with markers
- Filterable by evidence type
- Detailed evidence cards

### Evidence Detail Screen
- Tabbed interface for different views
- Metadata panel
- Chain of custody tracking
- Hash verification

### Report Export Screen
- Export options configuration
- Format selection (PDF, ZIP, CSV)
- Preview functionality
- Generation controls

## Technology Stack

- **Electron**: Cross-platform desktop application framework
- **HTML5/CSS3**: Modern web technologies
- **JavaScript**: Frontend interactivity
- **Inter Font**: Professional typography

## Installation

```bash
npm install
npm start
```

## Security Considerations

- All processing occurs locally
- No external network requests
- Secure evidence handling
- Immutable evidence storage