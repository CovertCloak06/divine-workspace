export default function (plop) {
  // Component generator
  plop.setGenerator('component', {
    description: 'Create a new component',
    prompts: [
      {
        type: 'input',
        name: 'name',
        message: 'Component name (e.g., LessonCard):',
      },
      {
        type: 'list',
        name: 'type',
        message: 'Component type:',
        choices: ['core', 'service', 'component', 'util', 'manager'],
      },
    ],
    actions: [
      {
        type: 'add',
        path: 'src/{{type}}s/{{pascalCase name}}.js',
        templateFile: 'plop-templates/component.hbs',
      },
      {
        type: 'add',
        path: 'tests/unit/{{pascalCase name}}.test.js',
        templateFile: 'plop-templates/test.hbs',
      },
    ],
  });

  // Lesson generator
  plop.setGenerator('lesson', {
    description: 'Create a new lesson',
    prompts: [
      {
        type: 'input',
        name: 'id',
        message: 'Lesson ID (e.g., html-02):',
      },
      {
        type: 'input',
        name: 'title',
        message: 'Lesson title:',
      },
      {
        type: 'list',
        name: 'category',
        message: 'Category:',
        choices: ['html', 'css', 'js', 'debugging', 'projects'],
      },
      {
        type: 'list',
        name: 'difficulty',
        message: 'Difficulty:',
        choices: ['beginner', 'intermediate', 'advanced'],
      },
    ],
    actions: [
      {
        type: 'add',
        path: 'lessons/{{category}}/{{id}}.json',
        templateFile: 'plop-templates/lesson.hbs',
      },
    ],
  });
}
