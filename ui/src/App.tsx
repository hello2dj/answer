import { RouterProvider, createHashRouter } from 'react-router-dom';

import './i18n/init';
import routes from '@/router';

function App() {
  const router = createHashRouter(routes);
  return <RouterProvider router={router} />;
}

export default App;
