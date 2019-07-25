#!/bin/bash

rm -rf target
shadow-cljs release node
npm publish
