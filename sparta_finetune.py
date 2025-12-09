#!/usr/bin/env python3
"""
SPARTA Model Fine-Tuning Script
Prepares SPARTA data for fine-tuning and provides training utilities.
This script creates training data and optionally fine-tunes a small language model.
"""

import json
import os
import random
from typing import List, Dict, Tuple
from dataclasses import dataclass

# Training data generation
@dataclass
class TrainingExample:
    """A single training example for QA."""
    question: str
    answer: str
    context: str
    technique_id: str


class SPARTATrainingDataGenerator:
    """Generate training data from SPARTA database for model fine-tuning."""
    
    def __init__(self, database_path: str = "sparta_database.json"):
        self.database_path = database_path
        self.database = None
        self.tactics_info = {
            "ST0001": ("Reconnaissance", "gathering information about space systems"),
            "ST0002": ("Resource Development", "establishing resources for operations"),
            "ST0003": ("Initial Access", "gaining initial entry to space systems"),
            "ST0004": ("Execution", "running malicious code on spacecraft"),
            "ST0005": ("Persistence", "maintaining access to spacecraft"),
            "ST0006": ("Defense Evasion", "avoiding detection"),
            "ST0007": ("Lateral Movement", "moving through space system environments"),
            "ST0008": ("Exfiltration", "stealing data from space systems"),
            "ST0009": ("Impact", "manipulating, interrupting, or destroying space systems")
        }
        
    def load_database(self):
        """Load the SPARTA database."""
        with open(self.database_path, 'r', encoding='utf-8') as f:
            self.database = json.load(f)
        print(f"Loaded {len(self.database)} entries")
        
    def generate_qa_pairs(self) -> List[TrainingExample]:
        """Generate question-answer pairs from the database."""
        if self.database is None:
            self.load_database()
            
        examples = []
        
        for entry in self.database:
            # Generate multiple question types for each entry
            examples.extend(self._generate_definition_questions(entry))
            examples.extend(self._generate_tactic_questions(entry))
            examples.extend(self._generate_description_questions(entry))
            examples.extend(self._generate_how_questions(entry))
            
        return examples
    
    def _generate_definition_questions(self, entry: Dict) -> List[TrainingExample]:
        """Generate 'What is' style questions."""
        questions = [
            f"What is {entry['name']}?",
            f"Define {entry['name']} in space security.",
            f"Explain the {entry['name']} technique.",
        ]
        
        answer = f"{entry['name']} ({entry['id']}) is a {entry['type'].replace('_', ' ')} under the {entry['tactic']} tactic. {entry['description']}"
        
        return [
            TrainingExample(
                question=q,
                answer=answer,
                context=entry['description'],
                technique_id=entry['id']
            )
            for q in questions
        ]
    
    def _generate_tactic_questions(self, entry: Dict) -> List[TrainingExample]:
        """Generate tactic-related questions."""
        questions = [
            f"What tactic does {entry['name']} belong to?",
            f"Which attack category includes {entry['name']}?",
        ]
        
        tactic_desc = self.tactics_info.get(entry['tactic_id'], (entry['tactic'], ""))[1]
        answer = f"{entry['name']} belongs to the {entry['tactic']} tactic, which focuses on {tactic_desc}."
        
        return [
            TrainingExample(
                question=q,
                answer=answer,
                context=entry['description'],
                technique_id=entry['id']
            )
            for q in questions
        ]
    
    def _generate_description_questions(self, entry: Dict) -> List[TrainingExample]:
        """Generate detailed description questions."""
        questions = [
            f"How do threat actors use {entry['name']}?",
            f"Describe how {entry['name']} attacks work.",
        ]
        
        answer = f"In {entry['name']} attacks, {entry['description']}"
        
        return [
            TrainingExample(
                question=q,
                answer=answer,
                context=entry['description'],
                technique_id=entry['id']
            )
            for q in questions
        ]
    
    def _generate_how_questions(self, entry: Dict) -> List[TrainingExample]:
        """Generate how-to style questions."""
        examples = []
        
        # Defensive questions
        q = f"How can I defend against {entry['name']}?"
        a = f"To defend against {entry['name']}, you should implement countermeasures for the {entry['tactic']} tactic. This technique involves: {entry['description'][:200]}... Understanding this attack vector helps in developing appropriate defenses."
        
        examples.append(TrainingExample(
            question=q,
            answer=a,
            context=entry['description'],
            technique_id=entry['id']
        ))
        
        return examples
    
    def generate_tactic_summary_data(self) -> List[TrainingExample]:
        """Generate training data about tactics."""
        if self.database is None:
            self.load_database()
            
        examples = []
        
        for tactic_id, (tactic_name, tactic_desc) in self.tactics_info.items():
            techniques = [e for e in self.database if e['tactic_id'] == tactic_id and e['type'] == 'technique']
            
            technique_names = [t['name'] for t in techniques[:5]]
            technique_list = ", ".join(technique_names)
            
            questions = [
                f"What are the techniques in the {tactic_name} tactic?",
                f"List {tactic_name} attack techniques.",
                f"What attacks fall under {tactic_name}?",
            ]
            
            answer = f"The {tactic_name} tactic ({tactic_id}) focuses on {tactic_desc}. Key techniques include: {technique_list}. There are {len(techniques)} techniques in total under this tactic."
            
            for q in questions:
                examples.append(TrainingExample(
                    question=q,
                    answer=answer,
                    context=tactic_desc,
                    technique_id=tactic_id
                ))
        
        return examples
    
    def export_training_data(self, output_path: str = "sparta_training_data.json"):
        """Export training data in a format suitable for fine-tuning."""
        qa_pairs = self.generate_qa_pairs()
        tactic_data = self.generate_tactic_summary_data()
        
        all_examples = qa_pairs + tactic_data
        
        # Convert to JSON format
        training_data = []
        for ex in all_examples:
            training_data.append({
                "instruction": ex.question,
                "input": "",
                "output": ex.answer,
                "context": ex.context,
                "technique_id": ex.technique_id
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(training_data, f, indent=2, ensure_ascii=False)
        
        print(f"Exported {len(training_data)} training examples to {output_path}")
        return training_data
    
    def export_conversation_format(self, output_path: str = "sparta_conversations.json"):
        """Export in conversation format for chat model fine-tuning."""
        qa_pairs = self.generate_qa_pairs()
        tactic_data = self.generate_tactic_summary_data()
        
        all_examples = qa_pairs + tactic_data
        
        conversations = []
        for ex in all_examples:
            conv = {
                "conversations": [
                    {"role": "user", "content": ex.question},
                    {"role": "assistant", "content": ex.answer}
                ],
                "metadata": {
                    "technique_id": ex.technique_id,
                    "domain": "space_security"
                }
            }
            conversations.append(conv)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(conversations, f, indent=2, ensure_ascii=False)
        
        print(f"Exported {len(conversations)} conversations to {output_path}")
        return conversations
    
    def export_retrieval_corpus(self, output_path: str = "sparta_corpus.json"):
        """Export corpus for retrieval-augmented generation."""
        if self.database is None:
            self.load_database()
        
        corpus = []
        for entry in self.database:
            doc = {
                "id": entry['id'],
                "title": entry['name'],
                "text": entry['description'],
                "metadata": {
                    "type": entry['type'],
                    "tactic": entry['tactic'],
                    "tactic_id": entry['tactic_id']
                }
            }
            if entry.get('parent_id'):
                doc['metadata']['parent_id'] = entry['parent_id']
                doc['metadata']['parent_name'] = entry.get('parent_name')
            
            corpus.append(doc)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(corpus, f, indent=2, ensure_ascii=False)
        
        print(f"Exported {len(corpus)} documents to {output_path}")
        return corpus


def create_huggingface_dataset():
    """Create a Hugging Face compatible dataset."""
    try:
        from datasets import Dataset, DatasetDict
        
        generator = SPARTATrainingDataGenerator()
        training_data = generator.export_training_data()
        
        # Convert to HF format
        dataset = Dataset.from_list([
            {
                "instruction": d["instruction"],
                "input": d["input"],
                "output": d["output"]
            }
            for d in training_data
        ])
        
        # Split into train/test
        split_dataset = dataset.train_test_split(test_size=0.1, seed=42)
        
        dataset_dict = DatasetDict({
            'train': split_dataset['train'],
            'test': split_dataset['test']
        })
        
        # Save locally
        dataset_dict.save_to_disk("sparta_hf_dataset")
        print("Saved Hugging Face dataset to sparta_hf_dataset/")
        
        return dataset_dict
        
    except ImportError:
        print("datasets library not available. Install with: pip install datasets")
        return None


def fine_tune_model():
    """
    Example fine-tuning script using Hugging Face transformers.
    This is a template - actual training requires GPU resources.
    """
    try:
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            TrainingArguments,
            Trainer,
            DataCollatorForLanguageModeling
        )
        from datasets import load_from_disk
        from peft import LoraConfig, get_peft_model, TaskType
        
        print("="*80)
        print("SPARTA Model Fine-Tuning")
        print("="*80)
        
        # Configuration
        MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"  # Small model for demo
        OUTPUT_DIR = "./sparta_finetuned"
        
        print(f"Loading base model: {MODEL_NAME}")
        
        # Load tokenizer and model
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        tokenizer.pad_token = tokenizer.eos_token
        
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            torch_dtype="auto",
            device_map="auto"
        )
        
        # Configure LoRA for efficient fine-tuning
        lora_config = LoraConfig(
            task_type=TaskType.CAUSAL_LM,
            r=16,
            lora_alpha=32,
            lora_dropout=0.1,
            target_modules=["q_proj", "v_proj"]
        )
        
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()
        
        # Load dataset
        dataset = load_from_disk("sparta_hf_dataset")
        
        def tokenize_function(examples):
            prompts = []
            for inst, inp, out in zip(examples["instruction"], examples["input"], examples["output"]):
                prompt = f"### Instruction:\n{inst}\n\n### Response:\n{out}"
                prompts.append(prompt)
            
            return tokenizer(
                prompts,
                truncation=True,
                max_length=512,
                padding="max_length"
            )
        
        tokenized_dataset = dataset.map(tokenize_function, batched=True)
        
        # Training arguments
        training_args = TrainingArguments(
            output_dir=OUTPUT_DIR,
            num_train_epochs=3,
            per_device_train_batch_size=4,
            per_device_eval_batch_size=4,
            warmup_steps=100,
            weight_decay=0.01,
            logging_dir="./logs",
            logging_steps=10,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
        )
        
        # Data collator
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=tokenizer,
            mlm=False
        )
        
        # Initialize trainer
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=tokenized_dataset["train"],
            eval_dataset=tokenized_dataset["test"],
            data_collator=data_collator,
        )
        
        # Train
        print("Starting training...")
        trainer.train()
        
        # Save the model
        trainer.save_model(OUTPUT_DIR)
        tokenizer.save_pretrained(OUTPUT_DIR)
        
        print(f"Model saved to {OUTPUT_DIR}")
        
    except ImportError as e:
        print(f"Required libraries not available: {e}")
        print("Install with: pip install transformers peft datasets accelerate")
    except Exception as e:
        print(f"Error during fine-tuning: {e}")
        print("Fine-tuning requires GPU resources and sufficient memory.")


def main():
    """Main function to generate all training data."""
    print("="*80)
    print("SPARTA Training Data Generator")
    print("="*80)
    
    generator = SPARTATrainingDataGenerator()
    
    # Generate all formats
    print("\n1. Generating instruction-tuning data...")
    generator.export_training_data("sparta_training_data.json")
    
    print("\n2. Generating conversation format data...")
    generator.export_conversation_format("sparta_conversations.json")
    
    print("\n3. Generating retrieval corpus...")
    generator.export_retrieval_corpus("sparta_corpus.json")
    
    print("\n" + "="*80)
    print("Training Data Generation Complete!")
    print("="*80)
    print("\nGenerated files:")
    print("  - sparta_training_data.json: Instruction-tuning format")
    print("  - sparta_conversations.json: Chat/conversation format")
    print("  - sparta_corpus.json: Retrieval corpus for RAG")
    print("\nTo fine-tune a model:")
    print("  1. Install: pip install transformers peft datasets accelerate")
    print("  2. Run: python sparta_finetune.py --train")
    print("\nFor semantic search without fine-tuning:")
    print("  Run: python sparta_semantic_search.py --interactive")


if __name__ == "__main__":
    import sys
    
    if "--train" in sys.argv:
        # First generate training data
        generator = SPARTATrainingDataGenerator()
        generator.export_training_data()
        
        # Create HF dataset
        create_huggingface_dataset()
        
        # Run fine-tuning
        fine_tune_model()
    else:
        main()
