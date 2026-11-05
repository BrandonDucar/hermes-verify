"""Synthetic hook registration checks; no SDK, network or real tool actions."""

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "hermes_verify_registration", ROOT / "__init__.py",
    submodule_search_locations=[str(ROOT)],
)
PLUGIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLUGIN)


class Context:
    def __init__(self):
        self.hooks = {}
        self.skills = {}
        self.tools = {}

    def get_config(self, key, default=None):
        return default

    def register_hook(self, name, callback, **options):
        self.hooks[name] = (callback, options)

    def register_skill(self, name, source):
        self.skills[name] = source

    def register_tool(self, **declaration):
        self.tools[declaration['name']] = declaration


class RegistrationTests(unittest.TestCase):
    def test_stream_hold_is_explicit(self):
        context = Context()
        PLUGIN.register(context)
        self.assertEqual(context.hooks['transform_llm_output'][1], {'hold_stream': True})

    def test_callback_uses_public_response_text_and_future_kwargs(self):
        context = Context()
        PLUGIN.register(context)
        callback = context.hooks['transform_llm_output'][0]
        result = callback(response_text='The transfer completed.', session_id='synthetic',
                          platform='test', model='none', future_field=True)
        self.assertTrue(result.startswith('[hermes-verify] DECLARED / unverified'))
        self.assertTrue(result.endswith('The transfer completed.'))

    def test_unsupported_registration_api_does_not_fall_back(self):
        class OlderContext(Context):
            def register_hook(self, name, callback):
                self.hooks[name] = callback
        context = OlderContext()
        with self.assertRaises(TypeError):
            PLUGIN.register(context)
        self.assertEqual(context.hooks, {})
        self.assertEqual(context.tools, {})

    def test_skill_stays_in_plugin_tree(self):
        context = Context()
        PLUGIN.register(context)
        source = context.skills['receipts']
        self.assertEqual(source, ROOT / 'skills' / 'receipts' / 'SKILL.md')
        self.assertTrue(source.is_file())

    def test_nonstring_output_is_not_coerced_or_delivered(self):
        class Hostile:
            def __str__(self):
                raise AssertionError('must not run arbitrary formatting')
        result = PLUGIN._on_transform_llm_output(response_text=Hostile())
        self.assertIn('Content omitted: expected a plain string', result)

    def test_repeated_transform_is_idempotent(self):
        first = PLUGIN._on_transform_llm_output(response_text='A proposal, not execution.')
        self.assertEqual(PLUGIN._on_transform_llm_output(response_text=first), first)


if __name__ == '__main__':
    unittest.main()
