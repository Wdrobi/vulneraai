#!/usr/bin/env python3
"""Generate VulneraAI Block Diagram using Pillow"""

from PIL import Image, ImageDraw, ImageFont
import os

# Image dimensions
WIDTH = 1600
HEIGHT = 1200
BG_COLOR = (10, 14, 39)  # Dark navy

# Create image
img = Image.new('RGB', (WIDTH, HEIGHT), color=BG_COLOR)
draw = ImageDraw.Draw(img)

# Colors
COLOR_FRONTEND = (0, 217, 255)      # Cyan
COLOR_API = (255, 0, 110)            # Pink/Magenta
COLOR_SERVICES = (0, 255, 136)       # Green
COLOR_DATA = (255, 170, 0)           # Orange
COLOR_TEXT = (255, 255, 255)         # White
COLOR_TEXT_DARK = (0, 0, 0)          # Black

# Try to load a font, fall back to default
try:
    title_font = ImageFont.truetype("arial.ttf", 24)
    header_font = ImageFont.truetype("arial.ttf", 18)
    normal_font = ImageFont.truetype("arial.ttf", 14)
    small_font = ImageFont.truetype("arial.ttf", 12)
except:
    title_font = ImageFont.load_default()
    header_font = ImageFont.load_default()
    normal_font = ImageFont.load_default()
    small_font = ImageFont.load_default()

def draw_box(x, y, width, height, color, text="", text_color=COLOR_TEXT_DARK):
    """Draw a rounded rectangle box"""
    # Draw rectangle
    draw.rectangle([x, y, x + width, y + height], fill=color, outline=COLOR_TEXT, width=2)
    
    # Draw text if provided
    if text:
        lines = text.split('\n')
        line_height = 16
        total_height = len(lines) * line_height
        start_y = y + (height - total_height) // 2
        
        for i, line in enumerate(lines):
            bbox = draw.textbbox((0, 0), line, font=small_font)
            text_width = bbox[2] - bbox[0]
            text_x = x + (width - text_width) // 2
            text_y = start_y + i * line_height
            draw.text((text_x, text_y), line, fill=text_color, font=small_font)

def draw_arrow(x1, y1, x2, y2, color=COLOR_TEXT):
    """Draw an arrow from (x1,y1) to (x2,y2)"""
    draw.line([(x1, y1), (x2, y2)], fill=color, width=2)
    
    # Draw arrow head
    size = 10
    angle = 0.4
    dx = x2 - x1
    dy = y2 - y1
    length = (dx*dx + dy*dy) ** 0.5
    if length > 0:
        dx /= length
        dy /= length
        px = x2 - dx * size * 2
        py = y2 - dy * size * 2
        px1 = px - dy * size - dx * size
        py1 = py + dx * size - dy * size
        px2 = px + dy * size - dx * size
        py2 = py - dx * size - dy * size
        draw.polygon([(x2, y2), (px1, py1), (px2, py2)], fill=color)

# Title
draw.text((50, 20), "VulneraAI System Block Diagram", font=title_font, fill=COLOR_FRONTEND)

# Layer positions
y_frontend = 100
y_api = 300
y_services = 500
y_data = 900

# FRONTEND LAYER
draw.text((50, y_frontend - 50), "Frontend Layer", font=header_font, fill=COLOR_FRONTEND)

frontend_boxes = [
    (80, "Home Page"),
    (300, "Auth UI"),
    (520, "Scanner"),
    (740, "Dashboard"),
    (960, "Report Viewer")
]

for x, text in frontend_boxes:
    draw_box(x, y_frontend, 160, 80, COLOR_FRONTEND, text, COLOR_TEXT_DARK)

# API LAYER
draw.text((50, y_api - 50), "API Layer (REST Endpoints)", font=header_font, fill=COLOR_API)

api_boxes = [
    (200, "Auth\n/login\n/register"),
    (650, "Scan\n/scans"),
    (1100, "Reports\n/reports")
]

for x, text in api_boxes:
    draw_box(x, y_api, 250, 100, COLOR_API, text, COLOR_TEXT)

# SERVICES LAYER
draw.text((50, y_services - 50), "Services Layer", font=header_font, fill=COLOR_SERVICES)

service_boxes = [
    (50, "Auth Service\nJWT, Hash"),
    (280, "Scanner\nDetection"),
    (510, "Risk\nAssessor"),
    (740, "Report\nGenerator"),
    (970, "API\nIntegrations")
]

for x, text in service_boxes:
    draw_box(x, y_services, 200, 120, COLOR_SERVICES, text, COLOR_TEXT_DARK)

# DATA LAYER
draw.text((50, y_data - 50), "Data Layer", font=header_font, fill=COLOR_DATA)

data_boxes = [
    (200, "SQLite\nDatabase"),
    (500, "User\nModel"),
    (750, "Scan\nModel"),
    (1000, "Vulnerability\nModel"),
    (1250, "Config")
]

for x, text in data_boxes:
    draw_box(x, y_data, 200, 100, COLOR_DATA, text, COLOR_TEXT_DARK)

# Draw connections (Frontend -> API)
draw_arrow(160, y_frontend + 80, 325, y_api)        # Home
draw_arrow(380, y_frontend + 80, 325, y_api)        # Auth
draw_arrow(600, y_frontend + 80, 775, y_api)        # Scanner
draw_arrow(820, y_frontend + 80, 775, y_api)        # Dashboard
draw_arrow(1040, y_frontend + 80, 1225, y_api)      # Report

# Draw connections (API -> Services)
draw_arrow(325, y_api + 100, 150, y_services)       # Auth API
draw_arrow(775, y_api + 100, 380, y_services)       # Scan API
draw_arrow(1225, y_api + 100, 840, y_services)      # Reports API

# Draw connections (Services -> Data)
draw_arrow(150, y_services + 120, 300, y_data)      # Auth -> DB
draw_arrow(380, y_services + 120, 300, y_data)      # Scanner -> DB
draw_arrow(610, y_services + 120, 600, y_data)      # Risk -> DB
draw_arrow(840, y_services + 120, 850, y_data)      # Report -> DB

# Save image
output_file = "block_diagram.png"
img.save(output_file, quality=95)
print(f"✓ Block diagram created: {output_file}")
print(f"  Size: {WIDTH}x{HEIGHT}px")
