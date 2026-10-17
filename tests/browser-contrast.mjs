// Test-only, serialized by page.evaluate. No application code imports this file.
// Bounded CSS model: solid colors and one non-repeating/default-sized sRGB
// linear gradient behind a region. Unsupported paints fail instead of passing.
export function auditContrast(options = {}) {
  const failures = [], measurements = [];
  let textChecks = 0, controlChecks = 0, focusChecks = 0;
  const cache = new Map();
  const split = value => {
    const parts = []; let depth = 0, start = 0;
    for (let i = 0; i < value.length; i++) {
      if (value[i] === '(') depth++;
      if (value[i] === ')') depth--;
      if (value[i] === ',' && !depth) { parts.push(value.slice(start, i).trim()); start = i + 1; }
    }
    parts.push(value.slice(start).trim()); return parts;
  };
  const rgb = value => {
    if (!/^rgba?\(/.test(value)) throw Error('Unsupported computed color: ' + value);
    const numbers = value.match(/[\d.]+/g).map(Number);
    if (numbers.length < 3 || numbers.length > 4) throw Error('Unsupported RGB color');
    return [...numbers.slice(0, 3), numbers[3] ?? 1];
  };
  const over = (front, back) => {
    const alpha = front[3] + back[3] * (1 - front[3]);
    return alpha ? [0, 1, 2].map(i => (front[i] * front[3] + back[i] * back[3] * (1 - front[3])) / alpha).concat(alpha) : [0, 0, 0, 0];
  };
  const luminance = color => color.slice(0, 3).map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4).reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
  const ratio = (a, b) => (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
  const lowerBound = (a, b) => {
    const interval = colors => [luminance([0, 1, 2].map(i => Math.min(colors[0][i], colors[1][i]))), luminance([0, 1, 2].map(i => Math.max(colors[0][i], colors[1][i])))];
    const [amin, amax] = interval(a), [bmin, bmax] = interval(b);
    return amin > bmax ? ratio(amin, bmax) : bmin > amax ? ratio(bmin, amax) : 1;
  };
  const length = (value, dimension) => value.endsWith('%') ? parseFloat(value) * dimension / 100 : /^-?[\d.]+px$/.test(value) ? parseFloat(value) : NaN;
  const contains = (box, x, y) => x >= box.left && x <= box.right && y >= box.top && y <= box.bottom;
  const boxAt = (left, top, width, height) => ({left, top, right:left + width, bottom:top + height, width, height});
  function paint(element) {
    if (cache.has(element)) return cache.get(element);
    const cs = getComputedStyle(element), border = element.getBoundingClientRect();
    const record = {element, cs, color:rgb(cs.backgroundColor), opacity:Number(cs.opacity), gradient:null};
    // Filters/blending/transforms require a different paint model, never a guess.
    if (cs.filter !== 'none' || cs.mixBlendMode !== 'normal' || cs.transform !== 'none') throw Error('Unsupported compositing on ' + (element.id || element.tagName));
    if (cs.backgroundImage !== 'none') {
      const layers = split(cs.backgroundImage), painted = layers.map((image,index) => ({image,index})).filter(x => x.image !== 'none');
      if (painted.length !== 1 || !painted[0].image.startsWith('linear-gradient(')) throw Error('Unsupported background image: ' + cs.backgroundImage);
      const {image,index} = painted[0];
      const property = value => { const values = split(value); return values[index % values.length]; };
      if (property(cs.backgroundClip) !== 'border-box' || property(cs.backgroundBlendMode) !== 'normal' || property(cs.backgroundAttachment) !== 'scroll') throw Error('Unsupported gradient clipping/blending/attachment');
      const origin = property(cs.backgroundOrigin);
      let left = border.left, top = border.top, width = border.width, height = border.height;
      if (origin !== 'border-box') {
        left += parseFloat(cs.borderLeftWidth); top += parseFloat(cs.borderTopWidth);
        width -= parseFloat(cs.borderLeftWidth) + parseFloat(cs.borderRightWidth);
        height -= parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth);
      }
      if (origin === 'content-box') {
        left += parseFloat(cs.paddingLeft); top += parseFloat(cs.paddingTop);
        width -= parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight);
        height -= parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
      }
      if (!['border-box', 'padding-box', 'content-box'].includes(origin)) throw Error('Unsupported background origin');
      const sizes = property(cs.backgroundSize).split(/\s+/);
      const w = sizes[0] === 'auto' ? width : length(sizes[0], width);
      const h = (sizes[1] ?? 'auto') === 'auto' ? height : length(sizes[1], height);
      if (!(w > 0 && h > 0)) throw Error('Unsupported gradient size: ' + cs.backgroundSize);
      const position = (value, space) => length(value, space);
      const x = position(property(cs.backgroundPositionX), width - w), y = position(property(cs.backgroundPositionY), height - h);
      if (!Number.isFinite(x) || !Number.isFinite(y)) throw Error('Unsupported background position');
      const repeat = property(cs.backgroundRepeat);
      if (repeat !== 'no-repeat' && !(repeat === 'repeat' && w === width && h === height && x === 0 && y === 0)) throw Error('Unsupported repeated gradient');
      const area = boxAt(left + x, top + y, w, h);
      const args = split(image.slice(16, -1));
      let angle = 180;
      if (!/^rgba?\(/.test(args[0])) {
        const direction = args.shift();
        const named = {'to top':0, 'to right':90, 'to bottom':180, 'to left':270};
        if (direction in named) angle = named[direction];
        else if (/^-?[\d.]+deg$/.test(direction)) angle = parseFloat(direction);
        else throw Error('Unsupported gradient direction/interpolation: ' + direction);
      }
      const dx = Math.sin(angle * Math.PI / 180), dy = -Math.cos(angle * Math.PI / 180);
      const extent = Math.abs(w * dx) + Math.abs(h * dy);
      const stops = args.map(arg => {
        const match = arg.match(/^(rgba?\([^)]+\))(?:\s+(-?[\d.]+(?:%|px)))?$/);
        if (!match) throw Error('Unsupported gradient stop: ' + arg);
        return {color:rgb(match[1]), at:match[2] ? length(match[2], extent) / extent : null};
      });
      if (stops.length < 2) throw Error('Gradient requires two stops');
      stops[0].at ??= 0; stops.at(-1).at ??= 1;
      let previous = stops[0].at;
      for (const stop of stops) if (stop.at !== null) { stop.at = Math.max(previous, stop.at); previous = stop.at; }
      for (let i = 0; i < stops.length - 1; i++) {
        if (stops[i + 1].at !== null) continue;
        let end = i + 1; while (stops[end].at === null) end++;
        for (let j = i + 1; j < end; j++) stops[j].at = stops[i].at + (stops[end].at - stops[i].at) * (j - i) / (end - i);
        i = end - 1;
      }
      const project = (x, y) => .5 + ((x - area.left - w / 2) * dx + (y - area.top - h / 2) * dy) / extent;
      record.gradient = {area, stops, project, css:image};
    }
    cache.set(element, record); return record;
  }
  function gradientColor(gradient, t) {
    const stops = gradient.stops;
    if (t < stops[0].at) return stops[0].color;
    let end = 1; while (end < stops.length && t >= stops[end].at) end++;
    if (end === stops.length) return stops.at(-1).color;
    const a = stops[end - 1], b = stops[end], fraction = (t - a.at) / (b.at - a.at);
    // CSS interpolates sRGB stops with premultiplied alpha.
    const alpha = a.color[3] + (b.color[3] - a.color[3]) * fraction;
    return alpha ? [0, 1, 2].map(i => (a.color[i] * a.color[3] * (1 - fraction) + b.color[i] * b.color[3] * fraction) / alpha).concat(alpha) : [0, 0, 0, 0];
  }
  function measure(element, foreground, rectangles) {
    const chain = []; for (let node = element; node; node = node.parentElement) chain.push(paint(node));
    let minimum = Infinity, observed = Infinity; const regions = [];
    for (const rect of rectangles) {
      if (!rect.width || !rect.height) continue;
      const gradients = chain.filter(p => p.gradient).map(p => p.gradient);
      const xs = [rect.left, rect.right], ys = [rect.top, rect.bottom];
      for (const {area} of gradients) {
        for (const x of [area.left, area.right]) if (x > rect.left && x < rect.right) xs.push(x);
        for (const y of [area.top, area.bottom]) if (y > rect.top && y < rect.bottom) ys.push(y);
      }
      xs.sort((a,b) => a-b); ys.sort((a,b) => a-b);
      for (let ix = 1; ix < xs.length; ix++) for (let iy = 1; iy < ys.length; iy++) {
        const active = gradients.filter(g => contains(g.area, (xs[ix-1]+xs[ix])/2, (ys[iy-1]+ys[iy])/2));
        if (active.length > 1) throw Error('Overlapping gradient layers require a separate paint model');
        const gradient = active[0];
        const pixel = t => {
          let background = [0,0,0,0], text = foreground;
          for (const p of chain) {
            const own = p.gradient === gradient && gradient ? over(gradientColor(gradient, t), p.color) : p.color;
            background = over(background, own); text = over(text, own);
            background[3] *= p.opacity; text[3] *= p.opacity;
          }
          return {background:over(background,[255,255,255,1]), text:over(text,[255,255,255,1])};
        };
        if (!gradient) {
          const p = pixel(0), value = ratio(luminance(p.text), luminance(p.background));
          minimum = Math.min(minimum, value); observed = Math.min(observed, value); continue;
        }
        const projections = [xs[ix-1],xs[ix]].flatMap(x => [ys[iy-1],ys[iy]].map(y => gradient.project(x,y)));
        const start = Math.min(...projections), end = Math.max(...projections);
        const points = [start,end,...gradient.stops.map(s => s.at).filter(t => t > start && t < end)];
        // Include both sides of hard stops. Bounds below cover every color in
        // each continuous slice, not just a favorable pixel or gradient stop.
        for (let i = 0; i < 2048; i++) points.push(start + (end-start) * i/2048);
        points.sort((a,b) => a-b);
        for (let i = 1; i < points.length; i++) {
          const a = points[i-1], b = points[i]; if (a === b) continue;
          const lo = pixel(a), hi = pixel(b);
          minimum = Math.min(minimum, lowerBound([lo.text,hi.text],[lo.background,hi.background]));
          observed = Math.min(observed, ratio(luminance(lo.text),luminance(lo.background)),ratio(luminance(hi.text),luminance(hi.background)));
        }
        regions.push({paint:gradient.css, projection:[start,end], bounds:{left:xs[ix-1],right:xs[ix],top:ys[iy-1],bottom:ys[iy]}});
      }
    }
    if (!Number.isFinite(minimum)) throw Error('No measurable contrast region');
    return {ratio:minimum, sampledMinimum:observed, gradientRegions:regions};
  }
  const textRects = element => {
    const rectangles = [];
    for (const node of element.childNodes) if (node.nodeType === 3 && node.textContent.trim()) {
      const range = document.createRange(); range.selectNodeContents(node); rectangles.push(...range.getClientRects());
    }
    return rectangles.length ? rectangles : [...element.getClientRects()];
  };
  for (const element of document.querySelectorAll(options.selector || 'body *')) {
    // Keep the native-disabled policy consistent for a control and its subtree.
    // :disabled is semantic; opacity and ARIA-only declarations do not qualify.
    if (!element.getClientRects().length || element.closest(':disabled') || element.closest('fieldset:disabled') || element.classList.contains('sr-only') || element.closest('svg')) continue;
    const cs = getComputedStyle(element), ownText = [...element.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (ownText || element.matches('input,select,textarea')) {
      const result = measure(element,rgb(cs.color),textRects(element)); textChecks++;
      if (result.ratio < 4.5) failures.push({element:element.id || element.tagName,kind:'text',ratio:result.ratio});
      if (options.details) measurements.push({element:element.id || element.tagName,parent:element.parentElement?.id,foreground:cs.color,...result});
    }
    if (element.matches('input[type=number],input[type=text],textarea,select,button:not(.primary)') && parseFloat(cs.borderTopWidth) > 0) {
      const result = measure(element,rgb(cs.borderTopColor),[element.getBoundingClientRect()]); controlChecks++;
      if (result.ratio < 3) failures.push({element:element.id || element.tagName,kind:'control border',ratio:result.ratio});
    }
    if (element === document.activeElement && cs.outlineStyle !== 'none') {
      const result = measure(element.parentElement,rgb(cs.outlineColor),[element.getBoundingClientRect()]); focusChecks++;
      if (result.ratio < 3) failures.push({element:element.id || element.tagName,kind:'focus',ratio:result.ratio});
    }
  }
  return {failures,textChecks,controlChecks,focusChecks,...(options.details ? {measurements} : {})};
}
