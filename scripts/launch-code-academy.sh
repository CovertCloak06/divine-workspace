#!/bin/bash
cd /home/gh0st/dvn/divine-workspace
just dev-app code-academy &
sleep 3
xdg-open http://localhost:8011
