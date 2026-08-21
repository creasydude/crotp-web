import * as THREE from 'three';

export interface ThreeBgController {
  triggerPulse: (colorHex?: number) => void;
  destroy: () => void;
}

export function initThreeBackground(container: HTMLElement): ThreeBgController {
  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x06070a, 0.0018);

  const camera = new THREE.PerspectiveCamera(
    60,
    window.innerWidth / window.innerHeight,
    0.1,
    1000
  );
  camera.position.z = 180;

  const renderer = new THREE.WebGLRenderer({
    alpha: true,
    antialias: true,
    powerPreference: 'high-performance',
  });
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.domElement.style.position = 'fixed';
  renderer.domElement.style.top = '0';
  renderer.domElement.style.left = '0';
  renderer.domElement.style.width = '100vw';
  renderer.domElement.style.height = '100vh';
  renderer.domElement.style.pointerEvents = 'none';
  renderer.domElement.style.zIndex = '0';
  renderer.domElement.style.opacity = '0.85';
  container.appendChild(renderer.domElement);

  // 1. Particle Constellation
  const particleCount = window.innerWidth < 768 ? 90 : 160;
  const positions = new Float32Array(particleCount * 3);
  const velocities: { x: number; y: number; z: number }[] = [];
  const spread = 220;

  for (let i = 0; i < particleCount; i++) {
    positions[i * 3] = (Math.random() - 0.5) * spread;
    positions[i * 3 + 1] = (Math.random() - 0.5) * spread;
    positions[i * 3 + 2] = (Math.random() - 0.5) * 120;

    velocities.push({
      x: (Math.random() - 0.5) * 0.12,
      y: (Math.random() - 0.5) * 0.12,
      z: (Math.random() - 0.5) * 0.08,
    });
  }

  const particleGeometry = new THREE.BufferGeometry();
  particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));

  // Custom circular glowing particle texture
  const canvas = document.createElement('canvas');
  canvas.width = 64;
  canvas.height = 64;
  const ctx = canvas.getContext('2d')!;
  const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  grad.addColorStop(0, 'rgba(167, 139, 250, 1)');
  grad.addColorStop(0.3, 'rgba(139, 92, 246, 0.8)');
  grad.addColorStop(0.7, 'rgba(99, 102, 241, 0.2)');
  grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, 64, 64);
  const particleTexture = new THREE.CanvasTexture(canvas);

  const particleMaterial = new THREE.PointsMaterial({
    color: 0x9333ea,
    size: 4.5,
    map: particleTexture,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });

  const particleSystem = new THREE.Points(particleGeometry, particleMaterial);
  scene.add(particleSystem);

  // 2. Dynamic Connection Lines
  const maxLineConnections = 300;
  const linePositions = new Float32Array(maxLineConnections * 6);
  const lineGeometry = new THREE.BufferGeometry();
  lineGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));

  const lineMaterial = new THREE.LineSegments(
    lineGeometry,
    new THREE.LineBasicMaterial({
      color: 0x6366f1,
      transparent: true,
      opacity: 0.18,
      blending: THREE.AdditiveBlending,
    })
  );
  scene.add(lineMaterial);

  // 3. Central Holographic Wireframe Core (Shield / Vault Sphere)
  const coreGroup = new THREE.Group();

  const icosahedronGeo = new THREE.IcosahedronGeometry(38, 1);
  const icosahedronMat = new THREE.MeshBasicMaterial({
    color: 0x8b5cf6,
    wireframe: true,
    transparent: true,
    opacity: 0.12,
  });
  const icosahedron = new THREE.Mesh(icosahedronGeo, icosahedronMat);
  coreGroup.add(icosahedron);

  const innerGeo = new THREE.TorusGeometry(26, 0.6, 16, 64);
  const innerMat = new THREE.MeshBasicMaterial({
    color: 0x06b6d4,
    wireframe: true,
    transparent: true,
    opacity: 0.2,
  });
  const innerTorus = new THREE.Mesh(innerGeo, innerMat);
  coreGroup.add(innerTorus);

  const outerRingGeo = new THREE.RingGeometry(48, 49, 48);
  const outerRingMat = new THREE.MeshBasicMaterial({
    color: 0xa855f7,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 0.08,
  });
  const outerRing = new THREE.Mesh(outerRingGeo, outerRingMat);
  coreGroup.add(outerRing);

  coreGroup.position.set(40, -10, -30);
  scene.add(coreGroup);

  // 4. Interactive Mouse Parallax
  let targetMouseX = 0;
  let targetMouseY = 0;
  let currentMouseX = 0;
  let currentMouseY = 0;

  const onMouseMove = (e: MouseEvent) => {
    const halfW = window.innerWidth / 2;
    const halfH = window.innerHeight / 2;
    targetMouseX = (e.clientX - halfW) / halfW;
    targetMouseY = (e.clientY - halfH) / halfH;
  };
  window.addEventListener('mousemove', onMouseMove, { passive: true });

  // 5. Resize Handler
  const onResize = () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  };
  window.addEventListener('resize', onResize);

  // 6. Pulse Wave on OTP tick / Copy
  let pulseActive = false;
  let pulseScale = 1;
  let pulseOpacity = 0.8;
  const pulseRingGeo = new THREE.RingGeometry(10, 12, 64);
  const pulseRingMat = new THREE.MeshBasicMaterial({
    color: 0x8b5cf6,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 0,
    blending: THREE.AdditiveBlending,
  });
  const pulseRing = new THREE.Mesh(pulseRingGeo, pulseRingMat);
  pulseRing.position.copy(coreGroup.position);
  scene.add(pulseRing);

  const triggerPulse = (colorHex: number = 0x8b5cf6) => {
    pulseRingMat.color.setHex(colorHex);
    pulseActive = true;
    pulseScale = 0.5;
    pulseOpacity = 0.75;
    pulseRing.visible = true;
  };

  // 7. Animation Loop
  let reqId: number;
  let clock = new THREE.Clock();

  const animate = () => {
    reqId = requestAnimationFrame(animate);
    const delta = clock.getDelta();
    const time = clock.getElapsedTime();

    // Smooth mouse parallax
    currentMouseX += (targetMouseX - currentMouseX) * 0.04;
    currentMouseY += (targetMouseY - currentMouseY) * 0.04;

    camera.position.x = currentMouseX * 18;
    camera.position.y = -currentMouseY * 14;
    camera.lookAt(0, 0, 0);

    // Rotate core geometry
    coreGroup.rotation.x = time * 0.12;
    coreGroup.rotation.y = time * 0.18;
    innerTorus.rotation.x = time * 0.35;
    innerTorus.rotation.y = time * 0.25;
    outerRing.rotation.z = time * 0.08;

    // Update particles
    const posAttr = particleGeometry.attributes.position as THREE.BufferAttribute;
    const posArray = posAttr.array as Float32Array;

    for (let i = 0; i < particleCount; i++) {
      const idx = i * 3;
      posArray[idx] += velocities[i].x;
      posArray[idx + 1] += velocities[i].y;
      posArray[idx + 2] += velocities[i].z;

      // Wrap boundaries
      if (Math.abs(posArray[idx]) > spread / 2) velocities[i].x *= -1;
      if (Math.abs(posArray[idx + 1]) > spread / 2) velocities[i].y *= -1;
      if (Math.abs(posArray[idx + 2]) > 60) velocities[i].z *= -1;
    }
    posAttr.needsUpdate = true;

    // Update dynamic connection lines
    let lineIdx = 0;
    const maxDist = 38;
    const maxDistSq = maxDist * maxDist;

    for (let i = 0; i < particleCount && lineIdx < maxLineConnections * 6; i++) {
      const ix = posArray[i * 3];
      const iy = posArray[i * 3 + 1];
      const iz = posArray[i * 3 + 2];

      for (let j = i + 1; j < particleCount && lineIdx < maxLineConnections * 6; j++) {
        const jx = posArray[j * 3];
        const jy = posArray[j * 3 + 1];
        const jz = posArray[j * 3 + 2];

        const dx = ix - jx;
        const dy = iy - jy;
        const dz = iz - jz;
        const distSq = dx * dx + dy * dy + dz * dz;

        if (distSq < maxDistSq) {
          linePositions[lineIdx++] = ix;
          linePositions[lineIdx++] = iy;
          linePositions[lineIdx++] = iz;
          linePositions[lineIdx++] = jx;
          linePositions[lineIdx++] = jy;
          linePositions[lineIdx++] = jz;
        }
      }
    }

    const linePosAttr = lineGeometry.attributes.position as THREE.BufferAttribute;
    linePosAttr.needsUpdate = true;
    lineGeometry.setDrawRange(0, lineIdx / 3);

    // Pulse wave progression
    if (pulseActive) {
      pulseScale += delta * 65;
      pulseOpacity -= delta * 0.9;
      pulseRing.scale.set(pulseScale, pulseScale, pulseScale);
      pulseRingMat.opacity = Math.max(0, pulseOpacity);
      if (pulseOpacity <= 0) {
        pulseActive = false;
        pulseRing.visible = false;
      }
    }

    renderer.render(scene, camera);
  };

  animate();

  const destroy = () => {
    cancelAnimationFrame(reqId);
    window.removeEventListener('mousemove', onMouseMove);
    window.removeEventListener('resize', onResize);
    if (renderer.domElement.parentElement) {
      renderer.domElement.parentElement.removeChild(renderer.domElement);
    }
    renderer.dispose();
  };

  return { triggerPulse, destroy };
}
